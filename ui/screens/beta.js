// Beta label and the one-time beta note.
// A "Beta" chip sits next to the version (Settings, About) while the app version is a pre-release. The
// projects screen shows a dismissible note until the user closes it (settings.ui.beta_note_done) with
// "Report a problem": the logs ZIP (same as Debug › Log › Share) is saved to Downloads, then the GitHub
// new-issue page opens in the browser (open_url).
(function () {
  const F = window.FOCA,
    ic = F.ic,
    esc = F.esc;
  const ISSUES_URL = "https://github.com/SinonApp/FOCA-rs/issues/new/choose";

  const version = () => (F.state.aboutMeta && F.state.aboutMeta.version) || "";
  /** Returns true for pre-release builds (2.0.0-beta.1, -rc.N, -alpha.N). */
  F.isBeta = () => /-(alpha|beta|rc)\b/i.test(version());
  /** The "Beta" chip, or "" for a release build. */
  F.betaChip = () =>
    F.isBeta() ? `<span class="pill warn beta-chip">${esc(F.t("beta.chip", "Бета"))}</span>` : "";

  const done = () => !!(((F.db && F.db.settings) || {}).ui || {}).beta_note_done;
  const dismiss = () =>
    F.api.settings_set({ ui: { beta_note_done: true } }).then(
      () => F.render(true),
      () => {},
    );

  F.betaNote = {
    /** Card for the projects screen; "" once dismissed or on a release build. */
    card: () =>
      !F.isBeta() || done()
        ? ""
        : `<div class="card pad beta-note" role="note">
        <div class="beta-note-h">${ic("info")}<p>${esc(F.t("beta.note", "Это бета-версия: что-то может сломаться. Пожалуйста, сообщайте о проблемах, это очень помогает."))}</p><button class="ib"
          data-act="beta-dismiss" aria-label="${esc(F.t("beta.close", "Закрыть"))}">${ic("x")}</button></div>
        <div class="beta-note-a"><button class="btn sm tonal" data-act="beta-report">${ic("bug")}${esc(F.t("beta.report", "Сообщить о проблеме"))}</button><button
          class="btn sm" data-act="beta-dismiss">${esc(F.t("beta.ok", "Понятно"))}</button></div>
      </div>`,
  };

  /** Saves the logs ZIP to Downloads, then opens the GitHub new-issue page. */
  F.reportProblem = () => {
    const logs = F.collectLogs
      ? F.collectLogs()
          .then(r => F.api.platform_save({ path: r.path, name: r.name }).then(() => r))
          .then(
            r =>
              F.snack(
                F.t(
                  "beta.logs_saved",
                  { name: r.name },
                  "Журналы сохранены: Download/FOCA-rs/{name}. Приложите их к issue",
                ),
                { ms: 7000 },
              ),
            e => F.snack(F.t("beta.logs_fail", { err: e.message || e }, "Журналы не собраны: {err}")),
          )
      : Promise.resolve();
    return logs.then(() =>
      F.api
        .open_url(ISSUES_URL)
        .catch(e =>
          F.snack(F.t("beta.open_fail", { err: e.message || e }, "Не удалось открыть GitHub: {err}")),
        ),
    );
  };

  Object.assign(F.actions, {
    "beta-dismiss": () => dismiss(),
    "beta-report": () => {
      dismiss();
      return F.reportProblem();
    },
    "beta-report-about": () => F.reportProblem(),
  });
})();
