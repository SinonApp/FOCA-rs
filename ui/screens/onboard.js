// First run. /terms shows the terms of use and disclaimer (before any other screen, including the PIN);
// /permissions explains what the app needs (notifications, background work, OEM autostart), then
// /welcome or /projects follows. /settings/terms shows the same terms read-only with the acceptance date.
// Consent is stored by the core: terms_get / terms_accept.
(function () {
  const F = window.FOCA,
    ui = F.ui,
    ic = F.ic,
    esc =
      F.esc ||
      (s =>
        String(s ?? "").replace(
          /[&<>"]/g,
          c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c],
        ));
  F.addIcons(
    '<symbol id="i-bell" viewBox="0 0 16 16"><path d="M4 11.5V7a4 4 0 0 1 8 0v4.5l1.2 1.5H2.8zM6.5 14a1.6 1.6 0 0 0 3 0"/></symbol>',
  );

  // Terms text. Its version is the core's TERMS_VERSION (crates/foca-engine/src/debug.rs): changing the
  // text bumps the version and the screen is shown again.
  const TERMS_V = "1",
    TERMS_DATE = "2026-11-20";
  // Dates follow the UI language: dd.mm.yyyy for ru/uk, "Nov 20, 2026" for en.
  const fdate = iso =>
    F.i18n && F.i18n.lang() === "en"
      ? new Date(iso + "T00:00:00").toLocaleDateString("en-US", {
          year: "numeric",
          month: "short",
          day: "numeric",
        })
      : F.fmt.dmy(iso);
  const POINTS = () => [
    [
      F.t("onboard.p_purpose_h", "Назначение"),
      F.t(
        "onboard.p_purpose_t",
        "FOCA-rs: инструмент для законного аудита безопасности и разведки по открытым источникам (OSINT): поиск опубликованных документов, разбор их метаданных и проверка собственных ресурсов.",
      ),
    ],
    [
      F.t("onboard.p_warranty_h", "Без гарантий"),
      F.t(
        "onboard.p_warranty_t",
        "Приложение распространяется «как\u00a0есть», без каких-либо гарантий, на условиях лицензии GNU\u00a0GPL версии\u00a03. Результаты могут быть неполными или ошибочными.",
      ),
    ],
    [
      F.t("onboard.p_dev_h", "Ответственность разработчика"),
      F.t(
        "onboard.p_dev_t",
        "Разработчик не несёт ответственности за любой прямой или косвенный ущерб, потерю данных, нарушение законов или прав третьих лиц, возникшие в результате использования приложения.",
      ),
    ],
    [
      F.t("onboard.p_user_h", "Ответственность пользователя"),
      F.t("onboard.p_user_t", "Вся ответственность за то, что, где и как вы проверяете, лежит на вас."),
    ],
    [
      F.t("onboard.p_active_h", "Активные проверки"),
      F.t(
        "onboard.p_active_t",
        "Запросы к серверам цели, порт-скан, проверки уязвимостей и перенос зоны. Только для своих ресурсов или при письменном разрешении владельца. Перед каждым активным запуском приложение попросит это подтвердить.",
      ),
    ],
    [
      F.t("onboard.p_criminal_h", "Уголовная ответственность"),
      F.t(
        "onboard.p_criminal_t",
        "Несанкционированный доступ к чужим информационным системам и вмешательство в их работу могут быть уголовно наказуемы. В Украине это, в частности, статья\u00a0361 Уголовного кодекса; в других странах действуют свои законы.",
      ),
    ],
    [
      F.t("onboard.p_pii_h", "Персональные данные"),
      F.t(
        "onboard.p_pii_t",
        "В документах встречаются имена, логины, адреса почты и телефоны. Вы сами соблюдаете законы о защите персональных данных: собираете только нужное, храните безопасно, удаляете по окончании работ.",
      ),
    ],
    [
      F.t("onboard.p_device_h", "Данные на устройстве"),
      F.t(
        "onboard.p_device_t",
        "Проекты, документы и отчёты хранятся только на этом устройстве в зашифрованном виде. Приложение не отправляет телеметрию и статистику использования.",
      ),
    ],
    [
      F.t("onboard.p_third_h", "Сторонние сервисы"),
      F.t(
        "onboard.p_third_t",
        "Запросы к веб-архивам, журналам сертификатов (CT), поисковым API и ИИ-сервису по вашему ключу идут от вашего имени и с вашего адреса (или через ваш прокси). Их правила использования вы соблюдаете сами.",
      ),
    ],
    [
      F.t("onboard.p_logs_h", "Журналы и отладка"),
      F.t(
        "onboard.p_logs_t",
        "Журналы работы хранятся локально. Выгрузка журналов: только по вашей команде, ключи и пароли из них вычищаются.",
      ),
    ],
    [
      F.t("onboard.p_changes_h", "Изменение условий"),
      F.t(
        "onboard.p_changes_t",
        "Если условия изменятся, приложение покажет их снова и попросит принять новую версию.",
      ),
    ],
  ];
  const CHECKS = () => [
    ["read", F.t("onboard.check_read", "Я прочитал и принимаю условия")],
    [
      "own",
      F.t(
        "onboard.check_own",
        "Буду проверять только свои ресурсы или ресурсы с письменным разрешением владельца",
      ),
    ],
    ["resp", F.t("onboard.check_resp", "Ответственность за использование несу я, а не разработчик")],
    ["age", F.t("onboard.check_age", "Мне есть 18 лет")],
  ];
  const terms = (F.state.terms = F.state.terms || { checks: {}, read: false, info: null, declined: false });
  F.termsVersion = TERMS_V;

  const textHtml = () => `
    <ol class="ob-points">${POINTS()
      .map(([h, d]) => `<li><b>${esc(h)}.</b> ${esc(d)}</li>`)
      .join("")}</ol>
    <p class="fhint ob-ver" id="ob-end">${esc(F.t("onboard.version_of", { v: TERMS_V, date: fdate(TERMS_DATE) }, "Версия\u00a0{v} от {date}"))}</p>`;
  const allChecked = () => CHECKS().every(([k]) => terms.checks[k]);
  const ready = () => allChecked() && terms.read;

  function renderTerms() {
    if (terms.declined)
      return `<div class="ob-declined">${ui.empty({
        icon: "lock",
        title: F.t("onboard.declined", "Условия не приняты"),
        text: F.t(
          "onboard.declined_text",
          "Без согласия с условиями приложением пользоваться нельзя. Закройте приложение или вернитесь к условиям.",
        ),
        action: `<button class="btn tonal"
        data-act="ob-back-terms">${esc(F.t("onboard.back_terms", "Вернуться к условиям"))}</button>`,
      })}</div>`;
    const why = whyText();
    return `
      <div class="ob-head"><img src="icon.png" alt=""
        class="ob-logo"><div><b class="ob-lt">FOCA-rs</b><p class="muted">${esc(F.t("onboard.terms_lead", "Прочитайте условия перед началом работы. Это займёт пару минут"))}</p></div></div>
      <div class="banner warn">${ic("alert")}<div><b>${esc(F.t("onboard.lawful", "FOCA-rs: только для законных проверок."))}</b> ${esc(F.t("onboard.lawful_text", "Проверяйте свои ресурсы или ресурсы, на которые есть письменное разрешение владельца."))}</div></div>
      <div class="card pad ob-text">${textHtml()}</div>
      <div class="list ob-checks">${CHECKS()
        .map(([k, l]) => ui.check(!!terms.checks[k], l, `ob-check:${k}`))
        .join("")}</div>
      <div class="foot ob-foot">
        <div class="foot-s"
          id="ob-why">${why ? `<span class="foot-w">${ic("info")}${esc(why)}</span>` : esc(F.t("onboard.can_go", "Можно продолжать"))}</div>
        <div class="btnrow ob-btns">
          <button class="btn" data-act="ob-decline">${esc(F.t("onboard.decline", "Не принимаю"))}</button>
          <button class="btn primary" id="ob-accept" data-act="ob-accept"
            ${ready() ? "" : "disabled"}>${ic("check")}${esc(F.t("onboard.accept", "Принимаю и\u00a0продолжаю"))}</button>
        </div>
      </div>`;
  }
  function whyText() {
    if (!terms.read) return F.t("onboard.why_read", "Прочитайте условия до конца");
    return allChecked() ? "" : F.t("onboard.why_checks", "Отметьте все пункты");
  }
  const syncFoot = () => {
    const b = document.getElementById("ob-accept"),
      w = document.getElementById("ob-why");
    if (b) b.disabled = !ready();
    const why = whyText();
    if (w)
      w.innerHTML = why
        ? `<span class="foot-w">${ic("info")}${esc(why)}</span>`
        : esc(F.t("onboard.can_go", "Можно продолжать"));
  };
  F.route("/terms", {
    title: () => F.t("onboard.terms_title", "Условия использования"),
    sub: "FOCA-rs",
    nav: false,
    back: false,
    actions: [],
    hideMini: true,
    render: () => renderTerms(),
    mount(page) {
      page.classList.add("ob-pg", "no-pb");
      F.onBack(() => true); // Back must not leave the first screen.
      const end = page.querySelector("#ob-end");
      if (!end || terms.read) return;
      // "Read" means the end of the text has scrolled into view (or the whole text fits on screen).
      const io = new IntersectionObserver(
        es => {
          if (es.some(e => e.isIntersecting)) {
            terms.read = true;
            syncFoot();
            io.disconnect();
          }
        },
        { threshold: 0.5 },
      );
      io.observe(end);
    },
  });
  Object.assign(F.actions, {
    "ob-check": (k, el) => {
      terms.checks[k] = !terms.checks[k];
      if (el) {
        el.classList.toggle("on", !!terms.checks[k]);
        el.setAttribute("aria-checked", !!terms.checks[k]);
      }
      syncFoot();
    },
    "ob-accept": () => {
      if (!ready()) return;
      F.api.terms_accept((terms.info && terms.info.version) || TERMS_V).then(
        r => {
          terms.info = r;
          terms.checks = {};
          terms.read = false;
          F.reset(["/permissions"]);
        },
        e =>
          F.snack(
            F.t("onboard.accept_fail", { err: e.message || e }, "Не удалось сохранить согласие: {err}"),
          ),
      );
    },
    "ob-decline": () => {
      F.api.platform_exit().then(
        r => {
          if (!r || r.demo || r.stub) {
            terms.declined = true;
            F.render(true);
          }
        },
        () => {
          terms.declined = true;
          F.render(true);
        },
      );
    },
    "ob-back-terms": () => {
      terms.declined = false;
      F.render(true);
    },
  });

  // ---------- /settings/terms: read-only ----------
  F.route("/settings/terms", {
    title: () => F.t("onboard.terms_title", "Условия использования"),
    sub: () => F.t("about.title", "О программе"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () => {
      const i = terms.info || {};
      const at = i.accepted_at
        ? fdate(String(i.accepted_at).slice(0, 10)) + ", " + String(i.accepted_at).slice(11, 16)
        : null;
      return `<div class="banner ${i.accepted ? "info" : "warn"}">${ic(i.accepted ? "check" : "alert")}<div>${i.accepted ? `<b>${esc(F.t("onboard.accepted_at", { at: at || "" }, "Приняты {at}."))}</b> ${esc(F.t("onboard.version", { v: i.accepted_version || TERMS_V }, "Версия\u00a0{v}."))}` : `<b>${esc(F.t("onboard.not_accepted", "Текущая версия условий ещё не принята."))}</b>`}</div></div>
        <div class="card pad ob-text">${textHtml()}</div>`;
    },
    mount(page) {
      page.classList.add("ob-pg");
      if (!terms.info)
        F.api.terms_get().then(
          r => {
            terms.info = r;
            if (F.current() === "/settings/terms") F.render(true);
          },
          () => {},
        );
    },
  });

  // ---------- /permissions: what the app needs ----------
  const perms = (F.state.perms = F.state.perms || { st: null, busy: false });
  const OEM_HELP = () => ({
    xiaomi: [
      "Xiaomi / Redmi / POCO (HyperOS, MIUI)",
      [
        [
          "autostart",
          F.t("onboard.oem_autostart", "Автозапуск"),
          F.t(
            "onboard.oem_autostart_t",
            "Настройки › Приложения › Все приложения › FOCA-rs › Автозапуск, включить. Без этого система закрывает скан после выхода из приложения.",
          ),
          "autostart",
        ],
        [
          "activity",
          F.t("onboard.oem_activity", "Контроль активности"),
          F.t(
            "onboard.oem_activity_t",
            "Настройки › Приложения › FOCA-rs › Контроль активности › «Нет ограничений».",
          ),
          "activity_control",
        ],
        // HyperOS/MIUI kills the scanning process when its card is swiped away from Recents, even with
        // autostart on.
        [
          "recents",
          F.t("onboard.oem_recents", "Карточка в «Недавних»"),
          F.t(
            "onboard.oem_recents_t",
            "Во время скана FOCA-rs скрывается из «Недавних», поэтому карточку не смахнуть (Настройки › Работа в фоне). Если выключить скрытие, закрепите карточку: зажмите её и нажмите замок.",
          ),
          "",
        ],
      ],
    ],
    samsung: [
      "Samsung (One UI)",
      [
        [
          "samsung",
          F.t("onboard.oem_samsung", "Батарея без ограничений"),
          F.t(
            "onboard.oem_samsung_t",
            "Настройки › Приложения › FOCA-rs › Батарея › «Без ограничений». Уберите приложение из «Спящих».",
          ),
          "battery",
        ],
      ],
    ],
    huawei: [
      "Huawei / Honor (EMUI)",
      [
        [
          "huawei",
          F.t("onboard.oem_huawei", "Запуск приложений"),
          F.t(
            "onboard.oem_huawei_t",
            "Настройки › Батарея › Запуск приложений › FOCA-rs. «Управлять вручную», включить все три переключателя.",
          ),
          "battery",
        ],
      ],
    ],
    oneplus: [
      "OnePlus / OPPO / realme",
      [
        [
          "oneplus",
          F.t("onboard.oem_oneplus", "Фоновая активность"),
          F.t(
            "onboard.oem_oneplus_t",
            "Настройки › Приложения › FOCA-rs › Батарея › «Разрешить фоновую активность».",
          ),
          "battery",
        ],
      ],
    ],
  });
  const oemKey = st => {
    const m = String((st && (st.manufacturer || "")) + " " + (st && (st.brand || ""))).toLowerCase();
    if ((st && st.oem === "xiaomi") || /xiaomi|redmi|poco/.test(m)) return "xiaomi";
    if (/samsung/.test(m) || (st && st.oem === "samsung")) return "samsung";
    if (/huawei|honor/.test(m)) return "huawei";
    if (/oneplus|oppo|realme/.test(m)) return "oneplus";
    return null;
  };
  // Steps the platform can report (MIUI autostart app-op, battery exemption): "on" | "off" | null (manual).
  const oemDetected = (k, st) => {
    if (k === "autostart") {
      const v = perms.bg && perms.bg.autostart;
      return v === "on" || v === "off" ? v : null;
    }
    if (k === "activity" && typeof st.battery === "boolean") return st.battery ? "on" : "off";
    return null;
  };
  const bgRefresh = () =>
    F.api.platform_bg_status
      ? F.api.platform_bg_status().then(
          bg => {
            const ch = JSON.stringify(bg || null) !== JSON.stringify(perms.bg || null);
            perms.bg = bg || null;
            if (ch && F.current() === "/permissions") F.render(true);
          },
          () => {},
        )
      : null;
  const permsRefresh = () => {
    bgRefresh();
    return F.api.platform_permissions_status().then(
      st => {
        const ch = JSON.stringify(st || {}) !== JSON.stringify(perms.st);
        perms.st = st || {};
        if (ch && F.current() === "/permissions") F.render(true);
      },
      () => {
        perms.st = perms.st || {};
      },
    );
  };
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && F.current && F.current() === "/permissions") permsRefresh();
  });
  const done = JSON.parse(
    (() => {
      try {
        return localStorage.getItem("foca-perm-done") || "{}";
      } catch (e) {
        return "{}";
      }
    })(),
  );
  const markDone = k => {
    done[k] = true;
    try {
      localStorage.setItem("foca-perm-done", JSON.stringify(done));
    } catch (e) {}
  };
  const stPill = ok =>
    ok
      ? `<span class="pill ok">${ic("check")}${esc(F.t("onboard.granted", "Выдано"))}</span>`
      : `<span class="pill warn">${ic("alert")}${esc(F.t("onboard.not_granted", "Не выдано"))}</span>`;
  function card(id, icon, title, why, ok, btn, act) {
    return `<div class="card pad ob-perm" id="ob-p-${id}">
      <div class="ob-ph">${ui.leadIcon(icon, ok ? "var(--ok)" : "var(--warn)")}<div class="ob-pt"><b>${esc(title)}</b>${stPill(ok)}</div></div>
      <p class="ob-pw">${esc(why)}</p>
      ${ok ? "" : `<button class="btn tonal block" data-act="${act}">${ic("open")}${esc(btn)}</button>`}
    </div>`;
  }
  function renderPerms() {
    const st = perms.st || {};
    const oem = oemKey(st),
      oemHelp = oem && OEM_HELP()[oem];
    return `
      <div class="ob-head"><div><b class="ob-lt">${esc(F.t("onboard.perms_head", "Что нужно приложению"))}</b><p class="muted">${esc(F.t("onboard.perms_lead", "Всё необязательно: отказ ничего не сломает, изменить можно в Настройках › Работа в фоне"))}</p></div></div>
      ${card("notif", "bell", F.t("onboard.notif", "Уведомления"), F.t("onboard.notif_why", "Показывают прогресс скана, пока приложение свёрнуто, и кнопку «Остановить». По ним Android понимает, что работа идёт в фоне."), st.notifications !== false, st.notifications_blocked ? F.t("onboard.notif_settings", "Открыть настройки уведомлений") : F.t("onboard.notif_allow", "Разрешить уведомления"), "ob-notif")}
      ${card("batt", "battery", F.t("onboard.batt", "Работа в фоне"), F.t("onboard.batt_why", "Исключение из оптимизации батареи: долгий скан не прервётся, когда экран выключен."), st.battery !== false, F.t("onboard.batt_allow", "Разрешить работу в фоне"), "ob-batt")}
      ${
        oemHelp
          ? `${ui.secH(oemHelp[0])}${oemHelp[1]
              .map(([k, t, d, what]) => {
                const det = oemDetected(k, st);
                const okd = det ? det === "on" : !!done[k];
                const pill =
                  det === "on"
                    ? `<span class="pill ok">${ic("check")}${esc(F.t("settings.step_on", "Включено"))}</span>`
                    : det === "off"
                      ? `<span class="pill warn">${ic("x")}${esc(F.t("settings.step_off", "Выключено"))}</span>`
                      : done[k]
                        ? `<span class="pill ok">${ic("check")}${esc(F.t("onboard.marked", "Отмечено"))}</span>`
                        : `<span class="pill mute">${esc(F.t("onboard.manual", "Вручную"))}</span>`;
                return `<div class="card pad ob-perm" data-oem-step="${k}" data-state="${det || "manual"}"><div class="ob-ph">${ui.leadIcon("gear", okd ? "var(--ok)" : "")}<div class="ob-pt"><b>${esc(t)}</b>${pill}</div></div>
        <p class="ob-pw">${esc(d).replace(/ › /g, ` <span class="ob-sep">›</span> `)}</p>
        <div class="btnrow">${
          what && det !== "on"
            ? `<button class="btn sm tonal"
          data-act="ob-oem:${what}:${k}">${ic("open")}${esc(F.t("common.open", "Открыть"))}</button>`
            : ""
        }${
          det
            ? ""
            : `<button class="btn sm"
          data-act="ob-oem-done:${k}">${esc(done[k] ? F.t("common.done", "Готово") : F.t("onboard.did_it", "Сделано"))}</button>`
        }</div></div>`;
              })
              .join("")}`
          : ""
      }
      <div class="foot ob-foot">
        <div class="btnrow ob-btns">${
          st.notifications !== false && st.battery !== false
            ? `<button class="btn primary" data-act="ob-next">${esc(F.t("onboard.next", "Далее"))}</button>`
            : `<button class="btn text ob-later" data-act="ob-next">${esc(F.t("onboard.later", "Позже"))}</button>
          <button class="btn primary" data-act="ob-all">${ic("check")}${esc(F.t("onboard.allow_all", "Разрешить всё"))}</button>`
        }</div>
      </div>`;
  }
  const afterOnboard = () => {
    let welcomed = false;
    try {
      welcomed = !!localStorage.getItem("foca-welcomed");
    } catch (e) {}
    F.reset([welcomed ? "/projects" : "/welcome"]);
  };
  F.route("/permissions", {
    title: () => F.t("onboard.perms_title", "Разрешения"),
    sub: "FOCA-rs",
    nav: false,
    back: false,
    actions: [],
    hideMini: true,
    render: () => (perms.st ? renderPerms() : ui.skeletonCards ? ui.skeletonCards(2) : ""),
    mount(page) {
      page.classList.add("ob-pg", "no-pb");
      if (!perms.st) permsRefresh();
    },
  });
  const ask = what =>
    what === "notif" ? F.api.platform_request_notifications() : F.api.platform_battery_settings("battery");
  Object.assign(F.actions, {
    "ob-notif": () =>
      ask("notif").then(
        r => {
          if (r && (r.demo || r.stub)) {
            perms.st = { ...perms.st, notifications: true };
            F.render(true);
          } else setTimeout(permsRefresh, 600);
        },
        e => F.snack(F.t("onboard.ask_fail", { err: e.message || e }, "Не удалось запросить: {err}")),
      ),
    "ob-batt": () =>
      ask("batt").then(
        r => {
          if (r && (r.demo || r.stub)) {
            perms.st = { ...perms.st, battery: true };
            F.render(true);
          } else if (r && !r.opened)
            F.snack(F.t("onboard.batt_manual", "Откройте настройки батареи вручную"));
        },
        e =>
          F.snack(
            F.t("onboard.settings_fail_err", { err: e.message || e }, "Не удалось открыть настройки: {err}"),
          ),
      ),
    // Sequential: notifications first (system dialog), then battery once the user returns to the app.
    "ob-all": () => {
      const st = perms.st || {};
      if (st.notifications === false) {
        perms.chain = st.battery === false;
        return F.actions["ob-notif"]();
      }
      if (st.battery === false) return F.actions["ob-batt"]();
    },
    "ob-oem": a => {
      const [what, k] = a.split(":");
      F.api.platform_battery_settings(what).then(
        r => {
          markDone(k);
          if (!r || (!r.opened && !r.demo))
            F.snack(
              F.t("onboard.oem_fail", "Экран прошивки не открылся. Найдите пункт вручную по подсказке"),
            );
          F.render(true);
        },
        () => F.snack(F.t("onboard.settings_fail", "Не удалось открыть настройки")),
      );
    },
    "ob-oem-done": k => {
      markDone(k);
      F.render(true);
    },
    "ob-next": () => afterOnboard(),
  });
  // "Allow all": after the notification prompt is answered (app regains focus), open the battery screen.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden || !perms.chain || F.current() !== "/permissions") return;
    perms.chain = false;
    setTimeout(() => {
      if ((perms.st || {}).battery === false) F.actions["ob-batt"]();
    }, 700);
  });

  // ---------- startup: terms come before any other screen ----------
  F.onboardStart = start =>
    F.api.terms_get().then(
      r => {
        terms.info = r;
        if (r && r.accepted) return start;
        return "/terms";
      },
      () => start,
    );
})();
