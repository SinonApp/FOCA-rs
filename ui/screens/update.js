// /settings/update: in-app update from GitHub Releases. The core checks the releases list (ETag cache,
// rate limit backoff), downloads the APK of this build's flavor into the app cache and verifies the
// signed SHA256SUMS.txt and the file's SHA-256; Android then checks the APK certificate, package and
// versionCode and starts a PackageInstaller session (platform_update_install). Release notes are
// remote text: they are escaped first and only then get the minimal markup of F.safeMd.
(function () {
  const F = window.FOCA,
    ic = F.ic,
    esc = F.esc,
    ui = F.ui;
  const RELEASES_URL = "https://github.com/SinonApp/FOCA-rs/releases";
  const U = (F.state.upd = F.state.upd || {
    view: null,
    perm: null,
    meta: null,
    busy: false,
    loaded: false,
    autoDone: false,
  });

  const flavor = () => (U.meta && U.meta.flavor) || (F.state.aboutMeta && F.state.aboutMeta.flavor) || "foss";
  const selfUpdate = () => !U.meta || U.meta.self_update !== false;
  const onUpdateRoute = () => F.cur && F.cur.path === "/settings/update";
  const rerender = () => onUpdateRoute() && F.render && F.render(true);

  function meta() {
    if (U.meta || !F.api.platform_device_info) return Promise.resolve(U.meta);
    return F.api
      .platform_device_info()
      .then(di => (U.meta = di || {}))
      .catch(() => (U.meta = {}));
  }
  function perm() {
    if (!F.api.platform_update_permission) return Promise.resolve(null);
    return F.api
      .platform_update_permission({})
      .then(p => (U.perm = p))
      .catch(() => (U.perm = { enabled: false, can_install: false }));
  }
  function load(force) {
    if (U.loaded && !force) return;
    U.loaded = true;
    meta()
      .then(() => Promise.all([F.api.update_status(flavor()), perm()]))
      .then(([v]) => {
        U.view = v;
        rerender();
      })
      .catch(() => {});
  }

  // Error texts by code; the core message stays as detail.
  const ERR = () => ({
    update_rate_limited: F.t(
      "update.err_rate",
      "GitHub временно ограничил запросы без входа. Проверка повторится позже.",
    ),
    update_net: F.t("update.err_net", "GitHub недоступен. Проверьте сеть или прокси."),
    update_http: F.t("update.err_http", "GitHub ответил ошибкой."),
    update_bad_response: F.t("update.err_bad_response", "Ответ GitHub не удалось разобрать."),
    update_not_signed: F.t(
      "update.err_not_signed",
      "В релизе нет подписанного файла контрольных сумм. Установка отклонена.",
    ),
    update_sig_invalid: F.t("update.err_sig", "Подпись релиза не прошла проверку. Установка отклонена."),
    update_sig_mismatch: F.t("update.err_sig", "Подпись релиза не прошла проверку. Установка отклонена."),
    update_sums_invalid: F.t("update.err_sums", "Файл контрольных сумм повреждён. Установка отклонена."),
    update_sums_missing: F.t(
      "update.err_sums_missing",
      "Для этого файла нет контрольной суммы. Установка отклонена.",
    ),
    update_sha_mismatch: F.t(
      "update.err_sha",
      "Контрольная сумма загруженного файла не совпала. Файл удалён.",
    ),
    update_size: F.t("update.err_size", "Размер загруженного файла не совпал. Попробуйте ещё раз."),
    update_bad_url: F.t("update.err_url", "Файл релиза указывает на чужой адрес. Установка отклонена."),
    update_cert_mismatch: F.t(
      "update.err_cert",
      "APK подписан другим сертификатом, чем установленное приложение. Установка отклонена.",
    ),
    update_package_mismatch: F.t(
      "update.err_package",
      "APK принадлежит другому приложению. Установка отклонена.",
    ),
    update_not_newer: F.t("update.err_not_newer", "Версия APK не новее установленной."),
    update_apk_unreadable: F.t("update.err_unreadable", "APK не удалось прочитать."),
    update_disabled: F.t("update.err_disabled", "В этой сборке установка обновлений отключена."),
    update_permission: F.t("update.err_permission", "Разрешите установку приложений из FOCA-rs."),
    update_install_failed: F.t("update.err_install", "Android не установил обновление."),
    update_install_cancelled: F.t("update.err_install_cancelled", "Установка отменена."),
    update_none: F.t("update.err_none", "Нет доступного обновления, проверьте ещё раз."),
  });
  const errText = e => (e && (ERR()[e.code] || e.message)) || "";
  const time = iso => (iso ? F.fmt.dmyhm(iso) : "");
  const epochTime = s => {
    const d = new Date(s * 1000);
    return `${F.fmt.pad(d.getHours())}:${F.fmt.pad(d.getMinutes())}`;
  };
  const mb = n => `${(n / 1048576).toFixed(1)} ${F.t("update.mb", "МБ")}`;

  // GitHub Markdown reduced to what F.safeMd understands: headings, lists, bold; images dropped,
  // links shown as their text (no remote URLs become clickable).
  function notesHtml(md) {
    const prepared = String(md || "")
      .split("\n")
      .filter(l => !/^\s*!\[[^\]]*\]\([^)]*\)\s*$/.test(l))
      .map(l =>
        l
          .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
          .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
          .replace(/^#{1,6} /, "## ")
          .replace(/^\* /, "- "),
      )
      .join("\n");
    return F.safeMd ? F.safeMd(prepared) : `<p>${esc(prepared)}</p>`;
  }

  function statusLine(v) {
    if (U.busy) return { cls: "info", text: F.t("update.checking", "Проверка…") };
    if (!v) return { cls: "info", text: F.t("update.loading", "Загрузка…") };
    if (v.backoff_until)
      return {
        cls: "warn",
        text: F.t(
          "update.rate_until",
          { t: epochTime(v.backoff_until) },
          "Лимит запросов GitHub. Повтор после {t}.",
        ),
      };
    if (v.error) return { cls: "bad", text: errText(v.error) };
    if (v.update)
      return { cls: "ok", text: F.t("update.available", { v: v.update.version }, "Доступна версия {v}") };
    if (v.checked_at) return { cls: "ok", text: F.t("update.up_to_date", "Установлена последняя версия") };
    return { cls: "info", text: F.t("update.never", "Ещё не проверялось") };
  }

  function downloadBlock(v) {
    const d = (v && v.download) || { phase: "idle" };
    const u = v.update;
    if (d.phase === "download" || d.phase === "verify") {
      const pct = d.total ? Math.min(100, Math.round((d.received / d.total) * 100)) : 0;
      const label =
        d.phase === "verify"
          ? F.t("update.verifying", "Проверка подписи и контрольной суммы…")
          : F.t(
              "update.downloading",
              { p: pct, a: mb(d.received || 0), b: mb(d.total || 0) },
              "Загрузка {p}% ({a} из {b})",
            );
      return `<div class="upd-prog" id="upd-prog"><div class="pbar"><i style="width:${d.phase === "verify" ? 100 : pct}%"></i></div>
        <p class="fhint">${esc(label)}</p></div>
        <button class="btn block" data-act="upd-cancel">${ic("x")}${esc(F.t("update.cancel", "Отменить загрузку"))}</button>`;
    }
    if (d.phase === "ready" && (!u || d.version === u.version)) {
      const p = U.perm || {};
      const blocked = p.enabled === false;
      const needPerm = !blocked && p.can_install === false;
      return `<div class="banner ok">${ic("shield")}<div>${esc(F.t("update.verified", "Подпись релиза и контрольная сумма проверены. Перед установкой Android сверит сертификат APK с установленным приложением."))}</div></div>
        ${
          blocked
            ? `<div class="banner info">${ic("info")}<div>${esc(F.t("update.android_only", "Установка доступна только в приложении Android. Откройте страницу релиза."))}</div></div>
               <button class="btn tonal block" data-act="upd-page">${ic("globe")}${esc(F.t("update.open_page", "Страница релиза"))}</button>`
            : needPerm
              ? `<div class="banner warn">${ic("alert")}<div>${esc(F.t("update.perm_text", "Android спросит разрешение «Установка неизвестных приложений» для FOCA-rs. Включите его и вернитесь."))}</div></div>
               <button class="btn primary block" data-act="upd-perm">${ic("shield")}${esc(F.t("update.perm_btn", "Разрешить установку"))}</button>`
              : `<button class="btn primary block" data-act="upd-install">${ic("download")}${esc(F.t("update.install", "Установить"))}</button>`
        }
        <button class="btn block st-mt" data-act="upd-cancel">${esc(F.t("update.discard", "Удалить загруженный файл"))}</button>`;
    }
    const failed =
      d.phase === "failed" || d.phase === "install_failed"
        ? `<div class="banner bad" id="upd-fail">${ic("alert")}<div><b>${esc(F.t("update.refused", "Обновление не установлено"))}</b> ${esc(errText(d.error))}</div></div>`
        : "";
    return `${failed}<button class="btn primary block" data-act="upd-download">${ic("download")}${esc(F.t("update.download", { s: mb(u.size) }, "Скачать и проверить ({s})"))}</button>`;
  }

  function schemaBanner(u) {
    if (!u || !u.schema || !u.schema.migrates) return "";
    return `<div class="banner warn" id="upd-schema">${ic("alert")}<div><b>${esc(F.t("update.schema_b", "Проекты будут перенесены на новую схему."))}</b> ${esc(F.t("update.schema_text", "Предыдущая версия не сможет их открыть. Сначала экспортируйте важные проекты."))}</div></div>`;
  }

  function render() {
    load();
    const v = U.view;
    const st = statusLine(v);
    const s = (v && v.settings) || { auto: true, wifi_only: true, prerelease: true };
    const u = v && v.update;
    const tg = (key, title, sub) =>
      `<div class="row tap st-tr" data-act="upd-set:${key}"><div class="body"><div class="t">${esc(title)}</div>${sub ? `<div class="s">${esc(sub)}</div>` : ""}</div><div class="tail">${ui.toggle(!!s[key], "upd-set:" + key, `aria-label="${esc(title)}"`)}</div></div>`;
    return `
      <div class="card pad upd-head">
        <div class="upd-st"><span class="pill ${st.cls}" id="upd-status">${esc(st.text)}</span></div>
        <p class="fhint">${esc(F.t("update.installed", { v: (v && v.current) || (F.state.aboutMeta || {}).version || "", f: flavor().toUpperCase() }, "Установлено: {v} ({f})"))}${
          v && v.checked_at
            ? ` · ${esc(F.t("update.checked", { t: time(v.checked_at) }, "проверено {t}"))}`
            : ""
        }</p>
        <button class="btn tonal block" data-act="upd-check" ${U.busy ? "disabled" : ""}>${ic("refresh")}${esc(F.t("update.check", "Проверить обновления"))}</button>
      </div>
      ${
        u
          ? `${ui.secH(F.t("update.new_version", { v: u.version }, "Версия {v}"))}
        <div class="card pad upd-rel" id="upd-rel">
          <div class="upd-chips"><span class="pill info">${esc(F.fmt.dmy(u.published_at))}</span><span class="pill">${esc(mb(u.size))}</span>${u.prerelease ? `<span class="pill warn">${esc(F.t("beta.chip", "Бета"))}</span>` : ""}</div>
          <p class="fhint mono upd-asset">${esc(u.asset)}</p>
          ${schemaBanner(u)}
          <div class="upd-notes md">${notesHtml(u.notes)}</div>
          ${downloadBlock(v)}
        </div>`
          : ""
      }
      ${ui.secH(F.t("update.settings", "Настройки проверки"))}
      <div class="list">
        ${tg("auto", F.t("update.auto", "Проверять автоматически"), F.t("update.auto_sub", "Раз в сутки при запуске"))}
        ${tg("wifi_only", F.t("update.wifi", "Только по Wi-Fi"), F.t("update.wifi_sub", "Автопроверка не тратит мобильный трафик"))}
        ${tg("prerelease", F.t("update.pre", "Включать бета-версии"), F.t("update.pre_sub", "Пока приложение в бете, новые версии выходят как пре-релизы"))}
      </div>
      <p class="fhint st-hint">${esc(F.t("update.privacy", "Проверка обращается к api.github.com и github.com через ваши настройки сети и прокси. Отправляется только версия приложения в User-Agent."))}</p>`;
  }

  function check() {
    if (U.busy) return;
    U.busy = true;
    rerender();
    F.api
      .update_check({ flavor: flavor() })
      .then(v => {
        U.view = v;
      })
      .catch(e => F.snack(errText(e) || String((e && e.message) || e)))
      .then(() => {
        U.busy = false;
        rerender();
      });
  }

  function install() {
    const v = U.view;
    const d = (v && v.download) || {};
    if (!d.path) return;
    F.api
      .platform_update_install({ path: d.path })
      .then(r => {
        if (r && r.ok) F.snack(F.t("update.confirm_hint", "Подтвердите установку в окне Android."));
        else {
          if (r && r.code === "update_permission") perm().then(rerender);
          F.snack(errText(r) || F.t("update.err_install", "Android не установил обновление."), { ms: 8000 });
        }
      })
      .catch(e => F.snack(errText(e) || String((e && e.message) || e)));
  }

  Object.assign(F.actions, {
    "upd-check": () => check(),
    "upd-set": (key, el) => {
      if (!["auto", "wifi_only", "prerelease"].includes(key) || !U.view) return;
      const next = !U.view.settings[key];
      U.view.settings = { ...U.view.settings, [key]: next };
      const tgl = el && (el.classList.contains("toggle") ? el : el.querySelector(".toggle"));
      if (tgl) F.actions.toggle(null, tgl);
      F.api
        .settings_set({ update: { [key]: next } })
        .then(() => (key === "prerelease" ? F.api.update_status(flavor()) : null))
        .then(v => {
          if (v) U.view = v;
          setTimeout(rerender, 120);
        })
        .catch(() => {});
    },
    "upd-download": () =>
      F.api
        .update_download(flavor())
        .then(() => F.api.update_status(flavor()))
        .then(v => {
          U.view = v;
          rerender();
        })
        .catch(e => F.snack(errText(e) || String((e && e.message) || e))),
    "upd-cancel": () =>
      F.api
        .update_cancel()
        .then(() => F.api.update_status(flavor()))
        .then(v => {
          U.view = v;
          rerender();
        })
        .catch(() => {}),
    "upd-perm": () =>
      F.api
        .platform_update_permission({ open: true })
        .then(p => {
          U.perm = p;
          rerender();
        })
        .catch(() => {}),
    "upd-install": () => {
      const u = U.view && U.view.update;
      if (!u || !u.schema || !u.schema.migrates) return install();
      F.sheet({
        title: F.t("update.schema_title", "Изменится формат проектов"),
        html: schemaBanner(u),
        footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" data-act="upd-install-go">${esc(F.t("update.install_anyway", "Установить"))}</button>`,
      });
    },
    "upd-install-go": () => {
      F.closeSheet && F.closeSheet();
      install();
    },
    "upd-page": () => {
      const url = (U.view && U.view.update && U.view.update.html_url) || RELEASES_URL;
      const safe = url.startsWith(RELEASES_URL) ? url : RELEASES_URL;
      if (F.api.platform_open_url) F.api.platform_open_url({ url: safe }).catch(() => F.snack(safe));
      else F.snack(safe);
    },
  });

  // Live download progress and install results (core `update` events, bridge `install_failed`).
  F.on("scan", ev => {
    if (!ev || ev.type !== "update" || !U.view) return;
    const d = { ...ev };
    delete d.type;
    U.view.download = d;
    if (ev.phase === "download" && onUpdateRoute()) {
      const bar = document.querySelector("#upd-prog .pbar i");
      const pct = d.total ? Math.min(100, Math.round((d.received / d.total) * 100)) : 0;
      if (bar) {
        bar.style.width = pct + "%";
        const label = document.querySelector("#upd-prog .fhint");
        if (label)
          label.textContent = F.t(
            "update.downloading",
            { p: pct, a: mb(d.received || 0), b: mb(d.total || 0) },
            "Загрузка {p}% ({a} из {b})",
          );
        return;
      }
    }
    rerender();
  });

  // Returning from the "Install unknown apps" screen: refresh the permission state.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && onUpdateRoute()) perm().then(rerender);
  });

  // Daily automatic check, once per app start; the core skips it when disabled, on mobile data with
  // Wi-Fi only, or when the last check is younger than a day.
  F.updateAutoCheck = () => {
    if (U.autoDone || !F.api.update_check) return;
    U.autoDone = true;
    meta()
      .then(() => (selfUpdate() ? F.api.update_check({ flavor: flavor(), auto: true }) : null))
      .then(v => {
        if (!v) return;
        U.view = v;
        if (v.outcome === "available" && v.update)
          F.snack(F.t("update.available", { v: v.update.version }, "Доступна версия {v}"), {
            label: F.t("update.open", "Открыть"),
            action: () => F.go("/settings/update"),
            ms: 10000,
          });
      })
      .catch(() => {});
  };
  if (F.isTauri) setTimeout(() => F.updateAutoCheck(), 15000);

  F.route("/settings/update", {
    title: () => F.t("update.title", "Обновления"),
    sub: () => F.t("settings.title", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => F.withStates(render, { loading: "cards" }),
    // Re-read the state the next time the screen opens (render loads once per visit).
    unmount: () => {
      U.loaded = false;
    },
  });
})();
