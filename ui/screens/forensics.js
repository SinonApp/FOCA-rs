// Document forensics (docs/API.md → doc_get, docs_search, import_offline, rules_*).
// - F.fx.docBlocks(doc): collapsible forensic sections of the document card (signatures/КЕП, PDF revisions,
//   bad redaction, hidden content, data connections, XMP history, attachments, PII, links, format details);
// - /p/docs-search: full-text search over document text with safe snippet highlighting;
// - /import: offline parsing of a folder, files or ZIP (no network, files never leave the device);
// - /p/rules: search rule presets and user regex rules with a "test" button;
// - F.fx.CODE: one-line notes of the forensic finding codes (finding card), F.fx.snippet for the global search.
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  const plural = (n, a, b, c) => F.plural(n, a, b, c); // language-aware (one/other in English)
  // Label tables keep Russian fallbacks and are translated on read with the key "<prefix>.<key>": `pos` is the
  // label index inside array values ("all" = every item, e.g. plural forms); list tables (arrays of tuples)
  // are keyed by the tuple id (item 0).
  const tt = (prefix, table, pos = 0) =>
    new Proxy(table, {
      get: (o, k) => {
        const v = o[k];
        if (typeof k !== "string" || k === "length" || !Object.prototype.hasOwnProperty.call(o, k)) return v;
        const key = `${prefix}.${Array.isArray(o) ? v[0] : k}`;
        if (!Array.isArray(v)) return typeof v === "string" ? F.t(key, v) : v;
        if (pos === "all") return v.map((x, i) => F.t(`${key}.${i}`, x));
        return v.map((x, i) => (i === pos ? F.t(key, x) : x));
      },
    });
  const fmtSize = kb => (F.dataUtil ? F.dataUtil.fmtSize(kb) : F.t("forensics.kb", { n: kb }, "{n} КБ"));
  const SEV_RANK = { crit: 0, high: 1, warn: 2, low: 3, info: 4 };
  const worst = list => list.reduce((m, s) => ((SEV_RANK[s] ?? 9) < (SEV_RANK[m] ?? 9) ? s : m), "");
  const kvr = (k, v, cls = "") =>
    v === "" || v == null
      ? ""
      : `<div class="kvr ${cls}"><div class="k">${k}</div><div class="v">${v}</div></div>`;
  const mono = v => `<span class="mono fx-break">${esc(v)}</span>`;
  const pill = (cls, text, icon) => `<span class="pill ${cls}">${icon ? ic(icon) : ""}${text}</span>`;
  /** ISO date-time → "дд.мм.гггг чч:мм" (keeps the input when it is not a date). */
  const dt = v => {
    const m = /^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d))?/.exec(String(v || ""));
    return m ? `${m[3]}.${m[2]}.${m[1]}${m[4] ? ` ${m[4]}:${m[5]}` : ""}` : String(v || "");
  };

  // ================= labels (Russian fallbacks, translated through tt) =================
  // One-line meaning of a forensic finding code (provenance.rule), shown on the finding card.
  const CODE = tt("forensics.code", {
    "doc.bad_redaction": "Текст закрыт прямоугольником, но остался в PDF: его можно выделить и скопировать.",
    "doc.modified_after_signing":
      "После подписи в файл дописали изменения. Видимое содержимое может отличаться от подписанного.",
    "doc.signature_digest_mismatch":
      "Хеш в подписи не совпадает с содержимым: документ изменён или повреждён.",
    "doc.signer_identity":
      "Сертификат подписи (КЕП) раскрывает ФИО, должность, организацию и маску РНОКПП подписанта.",
    "doc.signature_tsa_gap":
      "Время подписи и метка TSA расходятся больше чем на сутки. Возможна подпись задним числом.",
    "doc.hidden_content":
      "Скрытый текст (w:vanish) или скрытые строки, столбцы и листы: в файле есть невидимые данные.",
    "doc.pdf_removed_text":
      "PDF сохранён поверх старых версий: удалённый текст восстанавливается из прошлых ревизий.",
    "doc.pdf_revision_authors":
      "Ревизии PDF сохранены разными людьми или программами, видна цепочка согласования.",
    "doc.scan_without_text": "Скан без текстового слоя: содержимое не проверяется поиском, смотрите вручную.",
    "doc.data_connection":
      "Подключения к базам, .odc и сводные таблицы раскрывают серверы, базы и учётные записи.",
    "doc.lnk_host_mac": "Ярлык .lnk хранит имя компьютера, MAC-адрес и серийный номер тома автора.",
    "doc.lnk_unc_path": "Ярлык указывает на сетевую папку. Видны файловый сервер и структура каталогов.",
    "doc.pdb_user": "Путь к PDB в программе содержит папку пользователя: виден логин разработчика и проекты.",
    "doc.ai_generated": "Изображение создано нейросетью: в метаданных остались генератор, модель и промпт.",
    "doc.geodata": "Файл KML/GPX хранит координаты объектов и треков, часто с именами и временем.",
    "doc.sourcemap": "Карта исходников перечисляет файлы проекта и пути сборки, иногда с исходным кодом.",
    "doc.author_cluster": "Документы связаны общими следами: один автор, компьютер, шаблон или устройство.",
    "mail.internal_relay": "Заголовки Received раскрывают внутренние почтовые серверы и частные IP-адреса.",
    "mail.originating_ip": "X-Originating-IP раскрывает адрес компьютера отправителя.",
    "mail.internal_domain": "В Message-ID видно внутреннее имя почтового сервера или домена AD.",
    "mail.reply_to_mismatch":
      "Ответы уходят не отправителю, а на другой адрес. Признак фишинга или личного ящика.",
    "mail.exchange_x500": "Адреса X.500 раскрывают организацию и учётные записи Exchange.",
    "mail.m365_tenant": "В заголовках письма виден идентификатор арендатора Microsoft 365.",
    "cal.meeting_link": "Приглашение содержит ссылку на онлайн-встречу, посторонний может подключиться.",
    "pim.contact_pii": "Файл контактов содержит телефоны, адреса и даты рождения (значения маскированы).",
    "media.device_serial": "Серийный номер камеры/телефона связывает публикации, снятые одним устройством.",
    "zip.path_traversal": "Имена в архиве выходят за папку распаковки (Zip-Slip), архив враждебен.",
    pii: "Персональные данные в документе; значения проверены по контрольным суммам и хранятся только маскированными.",
    "doc.links": "Ссылки на облачные пространства и URL с токенами доступа (токены маскированы).",
    "doc.user_rule": "Сработало правило поиска проекта (Скоуп → Правила поиска).",
  });
  // Help article for a code (finding card → F.t("common.details", "Подробнее")).
  const CODE_HELP = {
    "doc.bad_redaction": "redaction-help",
    "doc.modified_after_signing": "kep-help",
    "doc.signature_digest_mismatch": "kep-help",
    "doc.signer_identity": "kep-help",
    "doc.signature_tsa_gap": "kep-help",
    pii: "pii-help",
    "pim.contact_pii": "pii-help",
    "doc.user_rule": "rules-help",
  };
  const SIG_KIND = tt("forensics.sig_kind", { pdf: "PDF", ooxml: "Office (XML-DSig)", vba: "Макросы VBA" });
  const HIDDEN = tt("forensics.hidden", {
    vanish: ["Скрытый текст (w:vanish)", "eye-off"],
    row: ["Скрытые строки", "grid"],
    column: ["Скрытые столбцы", "grid"],
    sheet: ["Скрытый лист", "grid"],
  });
  const XMP_ACTION = tt("forensics.xmp", {
    created: "Создан",
    saved: "Сохранён",
    converted: "Конвертирован",
    derived: "Создан на основе",
    edited: "Изменён",
    printed: "Напечатан",
    published: "Опубликован",
    managed: "Передан в DAM",
    produced: "Выпущен",
    copied: "Скопирован",
    cropped: "Обрезан",
    filtered: "Обработан фильтром",
    resized: "Изменён размер",
    signed: "Подписан",
  });
  const PII = tt("forensics.pii", {
    rnokpp: "РНОКПП (ІПН)",
    edrpou: "Код ЄДРПОУ",
    iban: "IBAN",
    card: "Банковская карта",
    passport: "Паспорт",
    id_card: "ID-карта",
    phone: "Телефон",
    marking: "Гриф ограничения доступа",
  });
  const PII_SHORT = tt("forensics.pii_short", {
    rnokpp: "РНОКПП",
    edrpou: "ЄДРПОУ",
    iban: "IBAN",
    card: "карта",
    passport: "паспорт",
    id_card: "ID-карта",
    phone: "телефон",
    marking: "гриф",
  });
  const SERVICE = tt("forensics.service", {
    google_docs: "Google Docs",
    google_drive: "Google Drive",
    notion: "Notion",
    trello: "Trello",
    share_point: "SharePoint",
    one_drive: "OneDrive",
    figma: "Figma",
    jira: "Jira",
    confluence: "Confluence",
    git_hub: "GitHub",
    git_lab: "GitLab",
    bitbucket: "Bitbucket",
    dropbox: "Dropbox",
    miro: "Miro",
    meeting: "Онлайн-встреча",
    azure_storage: "Azure Storage",
    aws_s3: "Amazon S3",
    google_storage: "Google Cloud Storage",
    slack: "Slack",
    discord: "Discord",
    teams: "Microsoft Teams",
    telegram: "Telegram",
  });
  const TOKEN = tt("forensics.token", {
    azure_sas: "SAS-подпись Azure",
    aws_presigned: "Подписанная ссылка AWS",
    bot_token: "Токен бота",
    userinfo: "Логин:пароль в адресе",
    webhook: "Вебхук",
    query: "Параметр-токен",
  });
  // Labels of the masked snippet parts (docs_search hits.masked: "pii", "pii:card", "secret:password", …).
  const maskedLabel = m => {
    const [k, v] = String(m).split(":");
    if (k === "pii") return v ? PII_SHORT[v] || v : F.t("forensics.pii_lc", "персональные данные");
    if (k === "secret")
      return v === "password"
        ? F.t("forensics.password", "пароль")
        : v
          ? F.t("forensics.secret_kind", { v }, "секрет ({v})")
          : F.t("forensics.secret", "секрет");
    return m;
  };
  const SKIP = tt("forensics.skip", {
    too_many_files: "больше лимита файлов",
    file_too_large: "файл больше 100 МБ",
    total_too_large: "превышен общий объём",
    not_a_file: "не файл",
    bad_data: "не удалось прочитать",
  });
  const ERR = tt("forensics.err", { timeout: "разбор дольше 30 секунд, пропущен" });

  // ================= safe snippet rendering =================
  /**
   * Snippet of the core: plain text with {{h:…}} (match) and {{s:…}} (masked secret/PII) markers. Every part
   * is escaped; the only markup is the highlight/mask wrapper, so document text never becomes HTML.
   */
  function snippet(s) {
    const str = String(s || "");
    let out = "",
      last = 0;
    for (const m of str.matchAll(/\{\{([hs]):([\s\S]*?)\}\}/g)) {
      out += esc(str.slice(last, m.index));
      out +=
        m[1] === "h"
          ? `<mark class="fx-hl">${esc(m[2])}</mark>`
          : `<span class="fx-mask" title="${esc(F.t("forensics.value_hidden", "Значение скрыто"))}">${esc(m[2])}</span>`;
      last = m.index + m[0].length;
    }
    return out + esc(str.slice(last));
  }

  // ================= doc_get cache =================
  const CACHE = new Map(); // "<project>:<doc id>" → doc_get answer | { error }
  const pend = new Set();
  const openSecs = (F.state.fxOpen = F.state.fxOpen || new Set());
  const keyOf = id => `${(F.db.project || {}).id}:${id}`;
  function forensicsOf(id) {
    const k = keyOf(id);
    if (CACHE.has(k)) return CACHE.get(k);
    if (!pend.has(k)) {
      pend.add(k);
      F.api.doc_get(id).then(
        r => {
          pend.delete(k);
          CACHE.set(k, r || {});
          rerender(id);
        },
        e => {
          pend.delete(k);
          CACHE.set(k, { error: e.message || String(e) });
          rerender(id);
        },
      );
    }
    return null;
  }
  const rerender = id => {
    if (F.cur && F.cur.path === `/p/doc/${id}`) F.render(true);
  };
  F.on("db", ev => {
    if (ev.kind === "project" || ev.kind === "reset" || ev.kind === "init") CACHE.clear();
  });

  // ================= document card sections =================
  /** Collapsible section; `id` keeps the open state across re-renders. */
  function sec(id, icon, title, count, body, sev) {
    if (!body) return "";
    const open = openSecs.has(id);
    return `<details class="fx-sec" data-fx="${id}" ${open ? "open" : ""}>
      <summary><span class="fx-sic">${ic(icon)}</span><span class="fx-sh"><span class="fx-st">${title}</span>${count || sev ? `<span class="fx-meta">${count ? `<span class="fx-n">${count}</span>` : ""}${sev ? ui.sev(sev) : ""}</span>` : ""}</span>${ic("chev-down", "fx-chev")}</summary>
      <div class="fx-body">${body}</div></details>`;
  }

  function signaturesBlock(fx) {
    return fx.signatures
      .map(s => {
        const c = s.signer || {};
        const ts = s.timestamp || {};
        const gap =
          ts.gen_time && s.signing_time
            ? Math.round((Date.parse(ts.gen_time) - Date.parse(s.signing_time)) / 864e5)
            : 0;
        const digest =
          s.digest_valid === true
            ? pill("ok", F.t("forensics.hash_ok", "Хеш совпадает"), "check")
            : s.digest_valid === false
              ? pill("bad", F.t("forensics.hash_bad", "Хеш не совпадает"), "alert")
              : pill("mute", F.t("forensics.hash_na", "Хеш не проверялся"));
        return `<div class="fx-sig">
          <div class="fx-pills">${pill("info", esc(SIG_KIND[s.kind] || s.kind), "contract")}${s.modified_after_signing ? pill("bad", F.t("forensics.mod_after", "Правки после подписания"), "alert") : pill("ok", F.t("forensics.not_mod", "После подписи не менялся"), "check")}${digest}${c.edrpou || c.rnokpp_masked ? pill("vio", F.t("forensics.kep_ua", "КЕП (Украина)"), "shield") : ""}</div>
          <div class="kv fx-kv">
            ${kvr(F.t("forensics.signer", "Подписант"), esc(c.common_name || s.name || "-"))}
            ${kvr(F.t("forensics.title", "Должность"), esc(c.title || ""))}
            ${kvr(F.t("forensics.org", "Организация"), esc([c.organization, c.org_unit].filter(Boolean).join(" · ")))}
            ${kvr(F.t("forensics.edrpou", "ЄДРПОУ"), c.edrpou ? mono(c.edrpou) : "")}
            ${kvr(F.t("forensics.rnokpp", "РНОКПП"), c.rnokpp_masked ? `${mono(c.rnokpp_masked)}<div class="fx-sub">${esc(F.t("forensics.mask_only", "только маска"))}${c.rnokpp_valid ? esc(F.t("forensics.checksum_ok", " · контрольная сумма верна")) : ""}</div>` : "")}
            ${kvr("E-mail", c.email ? mono(c.email) : "")}
            ${kvr(F.t("forensics.acsk", "АЦСК"), esc(c.issuer_cn || c.issuer || ""))}
            ${kvr(F.t("forensics.sign_time", "Время подписи"), s.signing_time ? esc(dt(s.signing_time)) : "")}
            ${kvr(F.t("forensics.tsa", "Метка TSA"), ts.gen_time ? `${esc(dt(ts.gen_time))}${ts.tsa ? `<div class="fx-sub">${esc(ts.tsa)}</div>` : ""}${Math.abs(gap) > 1 ? `<div class="fx-sub fx-warn">${ic("alert")}${esc(F.t("forensics.tsa_gap", { n: plural(Math.abs(gap), F.t("forensics.day_one", "день"), F.t("forensics.day_few", "дня"), F.t("forensics.day_many", "дней")) }, "расходится с временем подписи на {n}"))}</div>` : ""}` : "")}
            ${kvr(F.t("forensics.reason", "Причина"), esc([s.reason, s.location].filter(Boolean).join(" · ")))}
            ${kvr(F.t("forensics.cert", "Сертификат"), c.not_before || c.not_after ? `${esc(dt(c.not_before).slice(0, 10))}-${esc(dt(c.not_after).slice(0, 10))}` : "")}
            ${kvr(F.t("forensics.algo", "Алгоритм"), esc([s.digest_algorithm, s.sub_filter].filter(Boolean).join(" · ")))}
            ${kvr(F.t("forensics.after_sign", "После подписи"), s.bytes_after ? esc(F.t("forensics.appended", { size: fmtSize(Math.ceil(s.bytes_after / 1024)) }, "дописано {size}")) : "")}
            ${kvr(F.t("forensics.where", "Где в файле"), mono(s.source || ""))}
          </div></div>`;
      })
      .join("")
      .concat(
        `<p class="fhint fx-note">${ic("info")}<span>${esc(F.t("forensics.sig_note", "Цепочка сертификатов и отзыв не проверяются: приложение показывает, что записано в подписи."))}</span></p>`,
      );
  }

  function revisionsBlock(fx) {
    return `<ol class="fx-tl">${fx.pdf_revisions
      .map(
        r => `<li class="fx-tli"><div class="fx-tlh"><b>${esc(F.t("forensics.revision", { n: r.revision }, "Ревизия {n}"))}</b>${r.modified ? `<span class="muted">${esc(dt(r.modified))}</span>` : ""}</div>
        <div class="fx-sub">${esc([r.author, r.creator || r.producer].filter(Boolean).join(" · ") || "-")} · ${plural(r.objects || 0, F.t("forensics.obj_one", "объект"), F.t("forensics.obj_few", "объекта"), F.t("forensics.obj_many", "объектов"))}</div>
        ${(r.removed_text || []).map(t => `<div class="fx-diff del"><span aria-hidden="true">−</span><span class="sr-only">${esc(F.t("forensics.removed", "Удалено:"))}</span>${esc(t)}</div>`).join("")}
        ${(r.added_text || []).map(t => `<div class="fx-diff ins"><span aria-hidden="true">+</span><span class="sr-only">${esc(F.t("forensics.added", "Добавлено:"))}</span>${esc(t)}</div>`).join("")}</li>`,
      )
      .join("")}</ol>`;
  }

  const redactionBlock = fx =>
    fx.bad_redactions
      .map(
        r => `<div class="card fx-red"><div class="fx-pills">${pill("crit", F.t("forensics.page", { n: r.page }, "Стр. {n}"), "alert")}${pill("mute", r.fill === "white" ? F.t("forensics.fill_white", "Белая заливка") : F.t("forensics.fill_black", "Чёрная заливка"))}</div>
        <div class="fx-quote">«${esc(r.text)}»</div></div>`,
      )
      .join("") +
    `<p class="fhint fx-note">${ic("info")}<span>${esc(F.t("forensics.red_note", "Под закраской остался настоящий текст. Показан короткий фрагмент (до 80 символов), значения персональных данных скрыты."))}</span></p>`;

  const hiddenBlock = fx =>
    `<div class="list">${fx.hidden_content
      .map(h => {
        const [t, i] = HIDDEN[h.kind] || [h.kind, "eye-off"];
        return ui.row({
          lead: ui.leadIcon(i, "var(--warn)"),
          title: `${esc(t)} · <span class="mono">${esc(h.location)}</span>`,
          sub: h.text
            ? `<span class="fx-quote">${esc(h.text)}</span>`
            : F.t("forensics.no_hidden_data", "данных в скрытой части нет"),
          cls: "fx-row",
        });
      })
      .join("")}</div>`;

  /** Data connections and pivot caches from format fields (xl:connection:*, xl:pivotCache*, chart:*, visio:data.*). */
  function connectionsBlock(fields) {
    const groups = new Map();
    const FIELD = {
      database: F.t("forensics.f_db", "База"),
      user: F.t("forensics.f_user", "Пользователь"),
      odcFile: F.t("forensics.f_odc", "Файл .odc"),
      credentialsFile: F.t("forensics.f_cred", "Файл учётных данных"),
      refreshedBy: F.t("forensics.f_refby", "Обновил"),
      refreshedDate: F.t("forensics.f_refdate", "Обновлено"),
      refreshedVersion: F.t("forensics.f_refver", "Версия Excel"),
      source: F.t("forensics.f_source", "Источник"),
      connectionId: F.t("forensics.f_connid", "Подключение"),
      externalRef: F.t("forensics.f_extref", "Внешняя ссылка"),
      connection: F.t("forensics.f_conn", "Строка подключения"),
      file: F.t("forensics.f_file", "Файл"),
      command: F.t("forensics.f_cmd", "Запрос"),
    };
    for (const [k, v] of Object.entries(fields)) {
      let m = /^xl:connection:(.+):(\w+)$/.exec(k);
      let g, f;
      if (m) [g, f] = [F.t("forensics.g_conn", { n: m[1] }, "Подключение «{n}»"), m[2]];
      else if ((m = /^xl:(pivotCache\d*):(\w+)$/.exec(k)))
        [g, f] = [F.t("forensics.g_pivot", { n: m[1] }, "Сводная таблица ({n})"), m[2]];
      else if ((m = /^chart:(.+):(externalRef)$/.exec(k)))
        [g, f] = [F.t("forensics.g_chart", { n: m[1] }, "Диаграмма {n}"), m[2]];
      else if ((m = /^visio:data\.(\d+)\.(\w+)$/.exec(k)))
        [g, f] = [F.t("forensics.g_visio", { n: m[1] }, "Данные Visio {n}"), m[2]];
      else continue;
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push([FIELD[f] || f, v]);
    }
    if (!groups.size) return "";
    return [...groups.entries()]
      .map(
        ([g, rows]) =>
          `<div class="fx-gh">${esc(g)}</div><div class="kv fx-kv">${rows.map(([k, v]) => kvr(esc(k), mono(v))).join("")}</div>`,
      )
      .join("");
  }

  /** Data connections parsed by the core (server, database, provider, user; passwords never stored). */
  function connListBlock(fx) {
    const list = fx.connections || [];
    if (!list.length) return "";
    const L = {
      server: F.t("forensics.c_server", "Сервер"),
      database: F.t("forensics.f_db", "База"),
      provider: F.t("forensics.c_provider", "Провайдер"),
      user: F.t("forensics.f_user", "Пользователь"),
      target: F.t("forensics.c_target", "Адрес или файл"),
    };
    return list
      .map(c => {
        const rows = Object.keys(L)
          .filter(k => c[k])
          .map(k => kvr(esc(L[k]), mono(c[k])));
        if (c.has_password)
          rows.push(
            kvr(
              esc(F.t("forensics.c_pass", "Пароль")),
              esc(F.t("forensics.c_pass_v", "был в файле, не сохраняется")),
            ),
          );
        return `<div class="fx-gh">${esc(c.name || c.kind)} <span class="mono">${esc(c.kind)}</span></div><div class="kv fx-kv">${rows.join("")}</div>`;
      })
      .join("");
  }
  /** Points from KML/GPX geodata. */
  function geoBlock(fx) {
    const pts = fx.geo_points || [];
    if (!pts.length) return "";
    return `<div class="kv fx-kv">${pts
      .slice(0, 50)
      .map(p =>
        kvr(
          esc(p.name || p.source),
          mono(
            `${p.lat.toFixed(5)}, ${p.lon.toFixed(5)}${p.alt != null ? ` · ${p.alt} m` : ""}${p.time ? ` · ${dt(p.time)}` : ""}`,
          ),
        ),
      )
      .join("")}</div>`;
  }
  /** Generative AI markers; the prompt is shown only here, never in reports. */
  function aiBlock(fx) {
    const a = fx.ai_generated;
    if (!a) return "";
    return `<div class="kv fx-kv">${[
      kvr(esc(F.t("forensics.ai_gen", "Генератор")), a.generator ? mono(a.generator) : ""),
      kvr(esc(F.t("forensics.ai_model", "Модель")), a.model ? mono(a.model) : ""),
      kvr(esc(F.t("forensics.ai_src", "Где найдено")), mono(a.source)),
      kvr(esc(F.t("forensics.ai_prompt", "Промпт")), a.prompt ? mono(a.prompt) : ""),
    ].join("")}</div>`;
  }
  /** Mail transport hops (Received), newest first. */
  function hopsBlock(fx) {
    const hops = fx.mail_hops || [];
    if (!hops.length) return "";
    return `<div class="list">${hops
      .map(
        (h, i) =>
          `<div class="row"><span class="fx-n">${i + 1}</span><span class="mono fx-break">${esc(h.from || "?")} → ${esc(h.by || "?")}${h.ip ? ` (${esc(h.ip)})` : ""}</span>${h.internal ? pill("warn", esc(F.t("forensics.hop_int", "внутренний"))) : ""}</div>`,
      )
      .join("")}</div>`;
  }
  /** Document facts: language, paper size, file identifier, author time zone, Office release. */
  function factsBlock(fx) {
    const f = fx.facts || {};
    const paper = [f.paper, f.page_size].filter(Boolean).join(" · ");
    const office = f.office_release
      ? `${esc(f.office_release)}${f.app_version ? ` <span class="muted">(AppVersion ${esc(f.app_version)})</span>` : ""}`
      : "";
    const rows =
      kvr(F.t("forensics.f_lang", "Язык документа"), f.language ? mono(f.language) : "") +
      kvr(F.t("forensics.f_paper", "Размер страницы"), esc(paper)) +
      kvr(F.t("forensics.f_tagged", "Теговый PDF"), f.tagged ? esc(F.t("forensics.yes", "да")) : "") +
      kvr(F.t("forensics.f_tz", "Часовой пояс автора"), f.tz_offset ? mono(f.tz_offset) : "") +
      kvr(F.t("forensics.f_office", "Версия Office"), office) +
      kvr(
        F.t("forensics.f_os_lang", "Язык ОС (по имени учётной записи)"),
        f.locale_hint ? mono(f.locale_hint) : "",
      ) +
      kvr(F.t("forensics.f_codepage", "Кодировка"), esc(f.code_page || "")) +
      kvr(F.t("forensics.f_file_id", "Идентификатор файла (/ID)"), f.file_id ? mono(f.file_id) : "");
    return rows ? `<div class="kv fx-kv">${rows}</div>` : "";
  }

  /** Fonts and form fields: plain lists. */
  function listBlock(items) {
    return items.length
      ? `<div class="kv fx-kv">${items
          .map(([k, v]) =>
            v ? kvr(esc(k), mono(v)) : `<div class="kvr fx-only"><div class="v">${mono(k)}</div></div>`,
          )
          .join("")}</div>`
      : "";
  }

  function xmpBlock(fx) {
    const ids = fx.xmp_ids || {};
    const idRows = [
      ["DocumentID", ids.document_id],
      ["InstanceID", ids.instance_id],
      ["OriginalDocumentID", ids.original_document_id],
      [F.t("forensics.derived_doc", "DerivedFrom (документ)"), ids.derived_from_document_id],
      [F.t("forensics.derived_ver", "DerivedFrom (версия)"), ids.derived_from_instance_id],
    ].filter(x => x[1]);
    if (!fx.xmp_history.length && !idRows.length) return "";
    return (
      (fx.xmp_history.length
        ? `<ol class="fx-tl">${fx.xmp_history
            .map(
              e => `<li class="fx-tli"><div class="fx-tlh"><b>${esc(XMP_ACTION[e.action] || e.action || F.t("forensics.event", "Событие"))}</b>${e.when ? `<span class="muted">${esc(dt(e.when))}</span>` : ""}</div>
            ${e.software_agent ? `<div class="fx-sub">${esc(e.software_agent)}</div>` : ""}
            ${e.parameters ? `<div class="fx-sub">${esc(e.parameters)}</div>` : ""}
            ${e.changed ? `<div class="fx-sub">${esc(F.t("forensics.changed", { v: e.changed }, "изменено: {v}"))}</div>` : ""}</li>`,
            )
            .join("")}</ol>`
        : "") +
      (idRows.length
        ? `<div class="fx-gh">${esc(F.t("forensics.xmp_ids", "Идентификаторы XMP"))}</div><div class="kv fx-kv">${idRows.map(([k, v]) => kvr(k, mono(v))).join("")}</div>
          <p class="fhint fx-note">${ic("info")}<span>${esc(F.t("forensics.docid_note", "Одинаковый DocumentID у разных файлов значит, что они сделаны из одного исходника."))}</span></p>`
        : "")
    );
  }

  const embeddedBlock = (fx, unsafe) =>
    `<div class="list">${fx.embedded
      .map(e => {
        const bad = unsafe.includes(e.name) || /(^|[\\/])\.\.([\\/]|$)|^[\\/]|^[A-Za-z]:/.test(e.name);
        const ext = String(e.format || "").toLowerCase();
        return ui.row({
          lead: `<span class="ext ${esc(ext)}">${esc(ext || "?")}</span>`,
          title: `<span class="fx-break">${esc(e.name)}</span>`,
          sub: bad ? pill("bad", F.t("forensics.zip_slip", "Опасный путь (Zip-Slip)"), "alert") : "",
          cls: "fx-row",
        });
      })
      .join("")}</div>`;

  function piiBlock(fx) {
    return (
      `<div class="list">${fx.pii
        .map(p =>
          ui.row({
            lead: ui.leadIcon(p.kind === "marking" ? "flag" : "user", "var(--bad)"),
            title: `${esc(PII[p.kind] || p.kind)} · ${plural(p.count, F.t("forensics.val_one", "значение"), F.t("forensics.val_few", "значения"), F.t("forensics.val_many", "значений"))}`,
            sub: `${ui.sev(p.sev)}${(p.samples || []).map(x => `<div class="mono fx-break fx-sample">${esc(x)}</div>`).join("")}${(p.details || []).length ? `<div class="fx-sub">${esc(p.details.join(", "))}</div>` : ""}${p.location ? `<div class="fx-sub">${ic("pin")}${esc(p.location)}</div>` : ""}`,
            cls: "fx-row",
          }),
        )
        .join("")}</div>` +
      `<p class="fhint fx-note">${ic("lock")}<span>${esc(F.t("forensics.pii_note", "Значения хранятся только маскированными. Полный номер не показывается и не попадает в отчёт."))}</span>${F.helpBtn ? F.helpBtn("pii-help", F.t("forensics.pii_t", "Персональные данные")) : ""}</p>`
    );
  }

  const linksBlock = fx =>
    `<div class="list">${fx.links
      .map(l =>
        ui.row({
          lead: ui.leadIcon(
            l.tokens && l.tokens.length ? "key" : "link",
            l.sev === "crit" ? "var(--crit)" : "",
          ),
          title: esc(SERVICE[l.service] || l.host || F.t("forensics.link", "Ссылка")),
          sub: `<div class="mono fx-break">${esc(l.url)}</div><div class="fx-pills">${ui.sev(l.sev)}${l.shared ? pill("warn", F.t("forensics.shared", "Общий доступ")) : ""}${l.internal ? pill("info", F.t("forensics.internal_addr", "Внутренний адрес")) : ""}${(l.tokens || []).map(t => pill("bad", `${esc(TOKEN[t.kind] || t.kind)}: ${esc(t.name)}`, "key")).join("")}${l.expires ? pill("mute", esc(F.t("forensics.until", { date: dt(l.expires) }, "до {date}"))) : ""}</div>`,
          cls: "fx-row",
        }),
      )
      .join("")}</div>`;

  // ---------- format details ----------
  const fieldsWith = (fields, pre) =>
    Object.fromEntries(
      Object.entries(fields)
        .filter(([k]) => k.startsWith(pre))
        .map(([k, v]) => [k.slice(pre.length), v]),
    );
  function lnkBlock(doc, fields) {
    const f = fieldsWith(fields, "lnk:");
    const l = doc.lnk || {};
    const rows = [
      [F.t("forensics.lnk_pc", "Компьютер"), f.machine_id || l.machine],
      [F.t("forensics.lnk_mac", "MAC-адрес"), f.mac || l.mac],
      [F.t("forensics.lnk_serial", "Серийный номер тома"), f.volume_serial || l.volume_serial],
      [F.t("forensics.lnk_label", "Метка тома"), f.volume_label],
      [F.t("forensics.lnk_drive", "Тип диска"), f.drive_type],
      [F.t("forensics.lnk_local", "Локальный путь"), f.local_base_path || l.target],
      [F.t("forensics.lnk_share", "Сетевой ресурс"), f.network_share],
      [F.t("forensics.lnk_unc", "Сетевой путь (UNC)"), f.network_path],
      [F.t("forensics.lnk_wd", "Рабочая папка"), f.working_dir],
      [F.t("forensics.lnk_args", "Аргументы"), f.arguments],
      [F.t("forensics.descr", "Описание"), f.description],
      [F.t("forensics.lnk_access", "Последний доступ"), f.access_time && dt(f.access_time)],
      [F.t("forensics.lnk_droid", "DROID файла"), f.droid_file_id],
    ].filter(x => x[1]);
    return rows.length ? `<div class="kv fx-kv">${rows.map(([k, v]) => kvr(k, mono(v))).join("")}</div>` : "";
  }
  function mailBlock(doc, fields) {
    const p = doc.ext === "msg" ? "msg:" : "eml:";
    const f = fieldsWith(fields, p);
    const rel = (F.sel && F.sel.related && F.sel.related("doc", doc.id)) || {};
    const people = (rel.people || []).filter(x => x.login !== doc.user.login);
    const received = Object.keys(f)
      .filter(k => /^received\.\d+$/.test(k))
      .sort()
      .map(k => f[k]);
    const internal = String(f.internal_ips || "")
      .split(/,\s*/)
      .filter(Boolean);
    const rows = [
      [F.t("forensics.m_sender", "Отправитель"), doc.user && !doc.user.nometa ? esc(doc.user.name) : ""],
      [
        F.t("forensics.m_replyto", "Ответ на (Reply-To)"),
        f["reply-to"]
          ? `${mono(f["reply-to"])}${f.reply_to_differs === "true" ? `<div class="fx-sub fx-warn">${ic("alert")}${esc(F.t("forensics.m_differs", "отличается от отправителя"))}</div>` : ""}`
          : "",
      ],
      ["Return-Path", f["return-path"] ? mono(f["return-path"]) : ""],
      [
        F.t("forensics.m_rcpt", "Получатели"),
        esc([f.display_to, f.display_cc].filter(Boolean).join("; ")) ||
          (people.length ? esc(people.map(x => x.name).join(", ")) : ""),
      ],
      ["Message-ID", f["message-id"] ? mono(f["message-id"]) : ""],
      [F.t("forensics.m_mailer", "Почтовая программа"), esc(f["x-mailer"] || f["user-agent"] || "")],
      [F.t("forensics.m_ip", "IP отправителя"), f.originating_ips ? mono(f.originating_ips) : ""],
      [F.t("forensics.m_internal", "Внутренние узлы"), f.internal_hosts ? mono(f.internal_hosts) : ""],
      [F.t("forensics.org", "Организация"), esc(f.organization || "")],
      [
        F.t("forensics.m_tenant", "Арендатор M365"),
        f["x-ms-exchange-crosstenant-id"] ? mono(f["x-ms-exchange-crosstenant-id"]) : "",
      ],
      ["DKIM", f.dkim_domain ? mono([f.dkim_domain, f.dkim_selector].filter(Boolean).join(" · ")) : ""],
      [F.t("forensics.m_x500", "X.500 отправителя"), f.sender_x500 ? mono(f.sender_x500) : ""],
    ];
    const mark = s => {
      let h = esc(s);
      internal.forEach(ip => {
        h = h.split(esc(ip)).join(`<mark class="fx-hl">${esc(ip)}</mark>`);
      });
      return h;
    };
    return (
      `<div class="kv fx-kv">${rows.map(([k, v]) => kvr(k, v)).join("")}</div>` +
      (received.length
        ? `<div class="fx-gh">${esc(F.t("forensics.rcv_chain", { n: received.length }, "Цепочка Received ({n})"))}</div><ol class="fx-rcv">${received
            .map(r => `<li class="mono fx-break">${mark(r)}</li>`)
            .join(
              "",
            )}</ol><p class="fhint fx-note">${ic("info")}<span>${esc(F.t("forensics.rcv_note", "Сверху: последний сервер, снизу, компьютер отправителя. Подсвечены внутренние адреса."))}</span></p>`
        : "")
    );
  }
  function icsBlock(fields) {
    const f = fieldsWith(fields, "ics:");
    const ev = new Map();
    Object.entries(f).forEach(([k, v]) => {
      const m = /^event\.(\d+)\.(\w+)$/.exec(k);
      if (!m) return;
      if (!ev.has(m[1])) ev.set(m[1], {});
      ev.get(m[1])[m[2]] = v;
    });
    const head = [
      [F.t("forensics.c_method", "Метод"), f.method],
      [F.t("forensics.c_tz", "Часовой пояс"), f["x-wr-timezone"]],
      [F.t("forensics.c_uid", "Домены UID"), f.uid_domains],
    ].filter(x => x[1]);
    return (
      (head.length ? `<div class="kv fx-kv">${head.map(([k, v]) => kvr(k, mono(v))).join("")}</div>` : "") +
      [...ev.values()]
        .map(
          e =>
            `<div class="fx-gh">${esc(e.summary || F.t("forensics.event", "Событие"))}</div><div class="kv fx-kv">${kvr(F.t("forensics.c_start", "Начало"), esc(dt(e.start)))}${kvr(F.t("forensics.c_place", "Место"), esc(e.location || ""))}${kvr(F.t("forensics.c_org", "Организатор"), e.organizer ? mono(e.organizer) : "")}${kvr(F.t("forensics.descr", "Описание"), esc(e.description || ""))}</div>`,
        )
        .join("") +
      (f.meeting_links
        ? `<div class="fx-gh">${esc(F.t("forensics.meet_links", "Ссылки на встречи"))}</div>${String(
            f.meeting_links,
          )
            .split(/,\s*|\s+/)
            .filter(Boolean)
            .map(u => `<div class="mono fx-break fx-sample">${esc(u)}</div>`)
            .join("")}`
        : "")
    );
  }
  function vcfBlock(fields) {
    const cards = new Map();
    const LBL = {
      fn: F.t("forensics.v_fn", "Имя"),
      org: F.t("forensics.org", "Организация"),
      title: F.t("forensics.title", "Должность"),
      role: F.t("forensics.v_role", "Роль"),
      tel: F.t("forensics.v_tel", "Телефон"),
      email: "E-mail",
      bday: F.t("forensics.v_bday", "Дата рождения"),
      adr: F.t("forensics.v_adr", "Адрес"),
      note: F.t("forensics.v_note", "Заметка"),
      nickname: F.t("forensics.v_nick", "Псевдоним"),
      impp: F.t("forensics.v_impp", "Мессенджер"),
      uid: "UID",
    };
    Object.entries(fields).forEach(([k, v]) => {
      const m = /^vcf:(\d+)\.(.+)$/.exec(k);
      if (!m) return;
      if (!cards.has(m[1])) cards.set(m[1], []);
      cards.get(m[1]).push([m[2], v]);
    });
    return [...cards.values()]
      .map(rows => {
        const name = (rows.find(r => r[0] === "fn") || [])[1] || F.t("forensics.contact", "Контакт");
        return `<div class="fx-gh">${esc(name)}</div><div class="kv fx-kv">${rows
          .filter(r => r[0] !== "fn")
          .map(([k, v]) => kvr(esc(LBL[k] || k), mono(v)))
          .join("")}</div>`;
      })
      .join("");
  }
  function mediaBlock(doc, fields) {
    const f = fieldsWith(fields, "media:");
    const make = f["com.apple.quicktime.make"] || "",
      model = f["com.apple.quicktime.model"] || "";
    const serial = f.camera_serial || f["com.apple.quicktime.camera.serial"] || "";
    const rows = [
      [F.t("forensics.md_device", "Устройство"), doc.camera || [make, model].filter(Boolean).join(" ")],
      [F.t("forensics.md_serial", "Серийный номер"), serial],
      [F.t("forensics.md_sw", "ПО"), f["com.apple.quicktime.software"]],
      [F.t("forensics.md_date", "Дата съёмки"), f.creation_date && dt(f.creation_date)],
      ["GPS", doc.gps ? `${doc.gps.lat.toFixed(4)}, ${doc.gps.lon.toFixed(4)} · ${doc.gps.place || ""}` : ""],
      [F.t("forensics.md_cont", "Контейнер"), [f.major_brand, f.handler].filter(Boolean).join(" · ")],
    ].filter(x => x[1]);
    return rows.length ? `<div class="kv fx-kv">${rows.map(([k, v]) => kvr(k, esc(v))).join("")}</div>` : "";
  }
  /** Remaining format fields (WPD, Publisher, InDesign, Visio, ZIP…) as a plain list. */
  function otherFields(fields) {
    const rest = Object.entries(fields).filter(
      ([k]) =>
        !/^(lnk|eml|msg|ics|vcf|media):|^xl:connection:|^xl:pivotCache|^chart:|^visio:data\./.test(k) &&
        k !== "zip:unsafe_names",
    );
    return rest.length
      ? `<div class="kv fx-kv">${rest.map(([k, v]) => kvr(`<span class="mono">${esc(k)}</span>`, mono(v))).join("")}</div>`
      : "";
  }

  /** Forensic sections of the document card (empty string when there is nothing to show). */
  function docBlocks(doc) {
    if (!doc || doc.status_code !== "analyzed") return "";
    const r = forensicsOf(doc.id);
    if (!r)
      return `${ui.secH(F.t("forensics.forensics", "Форензика"))}<div class="card pad fx-load" role="status">${ic("spin", "spin")}<span>${esc(F.t("forensics.loading", "Загрузка подписей, ревизий и скрытых данных…"))}</span></div>`;
    if (r.error)
      return `${ui.secH(F.t("forensics.forensics", "Форензика"))}<div class="banner warn">${ic("alert")}<div>${esc(F.t("forensics.load_err", { e: r.error }, "Не удалось получить данные форензики: {e}"))}</div></div>`;
    const fx = r.forensics;
    if (!fx) return "";
    const fields = fx.fields || {};
    const ext = doc.ext;
    const unsafe = String(fields["zip:unsafe_names"] || "")
      .split(/,\s*|\n/)
      .filter(Boolean);
    const fmt =
      ext === "lnk"
        ? [F.t("forensics.s_lnk", "Ярлык Windows"), "path", lnkBlock(doc, fields)]
        : ext === "eml" || ext === "msg"
          ? [F.t("forensics.s_mail", "Заголовки письма"), "mail", mailBlock(doc, fields)]
          : ext === "ics"
            ? [F.t("forensics.s_cal", "Календарь"), "clock", icsBlock(fields)]
            : ext === "vcf"
              ? [F.t("forensics.s_vcf", "Контакты"), "users", vcfBlock(fields)]
              : ["mp4", "mov", "heic"].includes(ext)
                ? [F.t("forensics.s_media", "Медиафайл"), "camera", mediaBlock(doc, fields)]
                : ["", "", ""];
    const conn = connectionsBlock(fields);
    const other = otherFields(fields);
    const facts = factsBlock(fx);
    const blocks = [
      facts && sec("facts", "doc", F.t("forensics.s_facts", "Сведения о документе"), "", facts),
      fx.signatures.length &&
        sec(
          "sig",
          "contract",
          F.t("forensics.s_sig", "Подписи и КЕП"),
          fx.signatures.length,
          signaturesBlock(fx),
          fx.signatures.some(s => s.modified_after_signing || s.digest_valid === false) ? "high" : "",
        ),
      fx.bad_redactions.length &&
        sec(
          "red",
          "eraser",
          F.t("forensics.s_red", "Плохое замазывание"),
          fx.bad_redactions.length,
          redactionBlock(fx),
          "crit",
        ),
      fx.pdf_revisions.length > 1 &&
        sec(
          "rev",
          "history",
          F.t("forensics.s_rev", "Ревизии PDF"),
          fx.pdf_revisions.length,
          revisionsBlock(fx),
          fx.pdf_revisions.some(x => (x.removed_text || []).length) ? "high" : "",
        ),
      fx.hidden_content.length &&
        sec(
          "hid",
          "eye-off",
          F.t("forensics.s_hidden", "Скрытое содержимое"),
          fx.hidden_content.length,
          hiddenBlock(fx),
          fx.hidden_content.some(h => h.text) ? "high" : "warn",
        ),
      fx.scan_without_text &&
        sec(
          "scan",
          "scan",
          F.t("forensics.s_scan", "Скан без текста"),
          "",
          `<p class="fx-p">${esc(F.t("forensics.scan_note", "Страницы состоят только из изображений: текст не извлекается, поиск и анализ его не видят. Проверьте документ вручную."))}</p>`,
          "warn",
        ),
      (conn || (fx.connections || []).length) &&
        sec(
          "conn",
          "db",
          F.t("forensics.s_conn", "Подключения к данным"),
          (fx.connections || []).length || "",
          connListBlock(fx) + (conn || ""),
          (fx.connections || []).some(c => c.has_password) ? "high" : "warn",
        ),
      (fx.mail_hops || []).length &&
        sec(
          "hops",
          "mail",
          F.t("forensics.s_hops", "Путь письма (Received)"),
          fx.mail_hops.length,
          hopsBlock(fx),
        ),
      (fx.geo_points || []).length &&
        sec("geo", "pin", F.t("forensics.s_geo", "Геоданные"), fx.geo_points.length, geoBlock(fx), "warn"),
      fx.ai_generated &&
        sec("ai", "spark", F.t("forensics.s_ai", "Сгенерировано ИИ"), "", aiBlock(fx), "low"),
      (fx.form_fields || []).length &&
        sec(
          "form",
          "note",
          F.t("forensics.s_form", "Поля формы"),
          fx.form_fields.length,
          listBlock(fx.form_fields.map(f => [f.name, f.value || ""])),
        ),
      (fx.fonts || []).length &&
        sec(
          "fonts",
          "doc",
          F.t("forensics.s_fonts", "Шрифты"),
          fx.fonts.length,
          listBlock(fx.fonts.map(f => [f, ""])),
        ),
      fmt[2] && sec("fmt", fmt[1], fmt[0], "", fmt[2]),
      fx.pii.length &&
        sec(
          "pii",
          "user",
          F.t("forensics.pii_t", "Персональные данные"),
          fx.pii.reduce((s, p) => s + p.count, 0),
          piiBlock(fx),
          worst(fx.pii.map(p => p.sev)),
        ),
      fx.links.length &&
        sec(
          "links",
          "link",
          F.t("forensics.s_links", "Облачные ссылки и токены"),
          fx.links.length,
          linksBlock(fx),
          worst(fx.links.map(l => l.sev)),
        ),
      (fx.xmp_history.length || fx.xmp_ids) &&
        sec(
          "xmp",
          "history",
          F.t("forensics.s_xmp", "История правок (XMP)"),
          fx.xmp_history.length,
          xmpBlock(fx),
        ),
      fx.embedded.length &&
        sec(
          "emb",
          "folder",
          ext === "zip" ? F.t("forensics.s_zip", "Файлы в архиве") : F.t("forensics.s_att", "Вложения"),
          fx.embedded.length,
          embeddedBlock(fx, unsafe),
          unsafe.length ? "high" : "",
        ),
      other && sec("other", "note", F.t("forensics.s_other", "Прочие поля формата"), "", other),
    ].filter(Boolean);
    if (!blocks.length) return "";
    return `${ui.secH(F.t("forensics.forensics", "Форензика"), blocks.length, F.helpBtn ? F.helpBtn("forensics-help", F.t("forensics.help", "Форензика документов")) : "")}<div class="fx-secs">${blocks.join("")}</div>`;
  }
  /** Keeps the open/closed state of the sections (called from the document card mount). */
  function mountDoc(page) {
    page.addEventListener(
      "toggle",
      e => {
        const d = e.target.closest && e.target.closest(".fx-sec");
        if (!d) return;
        if (d.open) openSecs.add(d.dataset.fx);
        else openSecs.delete(d.dataset.fx);
      },
      true,
    );
  }

  // ================= full-text search /p/docs-search =================
  const FTS = (F.state.fts = F.state.fts || { q: "", deleted: false, res: null, shown: 30, seq: 0 });
  const PAGE = 30;
  function hitRow(h) {
    const d = (F.db.docs || []).find(x => x.id === h.doc) || {
      ext: (h.name.split(".").pop() || "").toLowerCase(),
    };
    return `<div class="row tap fx-hit" data-act="go:/p/doc/${h.doc}" role="link" tabindex="0">
      <span class="ext ${esc(d.ext)}">${esc(d.ext)}</span>
      <div class="body"><div class="t fx-break">${esc(h.name)}</div>
        <div class="fx-snip">${snippet(h.snippet)}</div>
        ${h.in_name || h.deleted || (h.masked || []).length ? `<div class="fx-pills">${h.in_name ? pill("info", F.t("forensics.in_name", "Совпадение в имени")) : ""}${h.deleted ? pill("mute", F.t("forensics.in_trash", "В корзине"), "x") : ""}${(h.masked || []).length ? pill("warn", esc(F.t("forensics.masked_in", { v: [...new Set(h.masked.map(maskedLabel))].join(", ") }, "В фрагменте скрыто: {v}")), "lock") : ""}</div>` : ""}
      </div>${ic("chev", "chev")}</div>`;
  }
  function ftsResults() {
    const r = FTS.res;
    if (!FTS.q.trim())
      return `${ui.secH(F.t("forensics.how", "Как искать"))}<div class="card pad fx-tips"><ul>
        <li>${esc(F.t("forensics.tip_all", "Несколько слов документ должен содержать все:"))} <code>договір ТЕС-2</code></li>
        <li>${esc(F.t("forensics.tip_phrase", "Точная фраза в кавычках:"))} <code>"потужність приєднання"</code></li>
        <li>${esc(F.t("forensics.tip_minus", "Исключить слово минусом:"))} <code>звіт -2019</code></li>
        <li>${esc(F.t("forensics.tip_star", "Начало слова со звёздочкой:"))} <code>енерг*</code></li></ul>
        <p class="fhint">${ic("info")}<span>${esc(F.t("forensics.fts_note", "Ищется по имени и тексту документов проекта (первые 64 КБ текста каждого файла). Персональные данные и секреты в результатах скрыты."))}</span></p></div>`;
    if (!r)
      return `<div class="card pad fx-load" role="status">${ic("spin", "spin")}<span>${esc(F.t("forensics.searching", "Поиск…"))}</span></div>`;
    if (r.error)
      return `<div class="banner bad">${ic("alert")}<div>${esc(F.t("forensics.search_err", { e: r.error }, "Поиск не выполнен: {e}"))}</div></div>`;
    if (!r.total)
      return ui.empty({
        icon: "search",
        title: F.t("forensics.nothing", "Ничего не найдено"),
        text: F.t(
          "forensics.nothing_text",
          "Проверьте написание или уберите часть слов. Сканы без текстового слоя по тексту не ищутся.",
        ),
      });
    return `<div class="fx-cnt" role="status">${esc(F.t("forensics.found_n", { n: plural(r.total, F.t("forensics.doc_one", "документ"), F.t("forensics.doc_few", "документа"), F.t("forensics.doc_many", "документов")) }, "Найдено: {n}"))}</div>
      <div class="list fx-hits">${r.hits.map(hitRow).join("")}</div>
      ${r.hits.length < r.total ? `<button class="btn block fx-more" data-act="fts-more">${ic("chev-down")}${esc(F.t("forensics.show_more", { i: r.hits.length, n: r.total }, "Показать ещё ({i} из {n})"))}</button>` : ""}`;
  }
  function ftsRun(page, append) {
    const seq = ++FTS.seq;
    const q = FTS.q.trim();
    if (!q) {
      FTS.res = null;
      const box = page.querySelector("#fts-res");
      if (box) box.innerHTML = ftsResults();
      return;
    }
    const offset = append && FTS.res ? FTS.res.hits.length : 0;
    F.api.docs_search(q, { limit: PAGE, offset, include_deleted: FTS.deleted }).then(
      r => {
        if (seq !== FTS.seq) return;
        FTS.res = append && FTS.res ? { ...r, hits: FTS.res.hits.concat(r.hits) } : r;
        const box = page.querySelector("#fts-res");
        if (box) box.innerHTML = ftsResults();
      },
      e => {
        if (seq !== FTS.seq) return;
        FTS.res = { error: e.message || String(e) };
        const box = page.querySelector("#fts-res");
        if (box) box.innerHTML = ftsResults();
      },
    );
  }
  F.route("/p/docs-search", {
    title: () => F.t("forensics.fts", "Поиск по тексту"),
    sub: () => (F.project ? F.project.name : ""),
    back: true,
    tab: "data",
    actions: [],
    hideMini: true,
    render: () =>
      F.withStates(
        () => `<div class="field fx-field">${ic("search")}<input id="fts-q" type="search" value="${esc(FTS.q)}"
          placeholder="${esc(F.t("forensics.fts_ph", "Слова или фраза из документов"))}" autocomplete="off" enterkeyhint="search"
          aria-label="${esc(F.t("forensics.fts_aria", "Поиск по тексту документов"))}"></div>
        <div class="chips fx-chips"><button class="chip ${FTS.deleted ? "on" : ""}" data-act="fts-del"
          aria-pressed="${FTS.deleted}">${ic("trash")}${esc(F.t("forensics.incl_trash", "Включая корзину"))}</button></div>
        <div id="fts-res" aria-live="polite">${ftsResults()}</div>`,
        {
          loading: "list",
          empty: {
            icon: "doc",
            title: F.t("forensics.no_docs", "Документов пока нет"),
            text: F.t("forensics.no_docs_text", "Искать можно после скачивания или офлайн-разбора."),
          },
        },
      ),
    mount: page => {
      const inp = page.querySelector("#fts-q");
      if (!inp) return;
      let t = null;
      inp.addEventListener("input", () => {
        FTS.q = inp.value;
        clearTimeout(t);
        t = setTimeout(() => ftsRun(page), 250);
      });
      F.actions["fts-more"] = () => ftsRun(page, true);
      F.actions["fts-del"] = (_, el) => {
        FTS.deleted = !FTS.deleted;
        el.classList.toggle("on", FTS.deleted);
        el.setAttribute("aria-pressed", FTS.deleted);
        ftsRun(page);
      };
      page.addEventListener("keydown", e => {
        if ((e.key === "Enter" || e.key === " ") && e.target.classList.contains("fx-hit")) {
          e.preventDefault();
          e.target.click();
        }
      });
      if (FTS.q.trim() && !FTS.res) ftsRun(page);
      if (!FTS.q) setTimeout(() => inp.focus(), 250);
    },
  });

  /** Text matches for the global search (/p/search): a short section under the other results. */
  function globalText(query, box, limit) {
    const seq = (globalText.seq = (globalText.seq || 0) + 1);
    if (!box || String(query).trim().length < 2) return;
    F.api.docs_search(query, { limit }).then(
      r => {
        if (seq !== globalText.seq || !box.isConnected || !r.total) return;
        box.innerHTML =
          ui.secH(
            F.t("forensics.in_text", "В тексте документов"),
            r.total > r.hits.length
              ? F.t("forensics.n_of", { i: r.hits.length, n: r.total }, "{i} из {n}")
              : "",
            r.total > r.hits.length
              ? `<button class="sec-a" data-act="fts-open:${esc(query)}">${esc(F.t("common.all", "Все"))}</button>`
              : "",
          ) + `<div class="list fx-hits">${r.hits.map(hitRow).join("")}</div>`;
        const empty = box.parentElement && box.parentElement.querySelector(".empty");
        if (empty) empty.remove();
      },
      () => {},
    );
  }
  F.actions["fts-open"] = q => {
    FTS.q = q;
    FTS.res = null;
    F.go("/p/docs-search");
  };

  // ================= offline import /import =================
  const IMP = (F.state.imp = F.state.imp || {
    files: [],
    skipped: 0,
    truncated: false,
    bytes: 0,
    name: "",
    domain: "",
    into: "new",
    run: null,
    result: null,
  });
  const defName = () => {
    const d = new Date();
    return F.t(
      "forensics.def_name",
      { date: `${String(d.getDate()).padStart(2, "0")}.${String(d.getMonth() + 1).padStart(2, "0")}` },
      "Офлайн-разбор {date}",
    );
  };
  function impPicked() {
    if (!IMP.files.length) return "";
    const shown = IMP.files.slice(0, 5);
    return `<div class="card pad fx-picked"><div class="fx-tlh"><b>${plural(IMP.files.length, F.t("forensics.file_one", "файл"), F.t("forensics.file_few", "файла"), F.t("forensics.file_many", "файлов"))}</b><span class="muted">${esc(fmtSize(Math.ceil((IMP.bytes || 0) / 1024)))}</span></div>
      <ul class="fx-files">${shown.map(f => `<li class="fx-break">${esc(f.name)}</li>`).join("")}${IMP.files.length > shown.length ? `<li class="muted">${esc(F.t("forensics.and_more", { n: IMP.files.length - shown.length }, "и ещё {n}"))}</li>` : ""}</ul>
      ${IMP.skipped ? `<p class="fhint">${ic("info")}<span>${esc(F.t("forensics.not_copied", { n: plural(IMP.skipped, F.t("forensics.file_one", "файл"), F.t("forensics.file_few", "файла"), F.t("forensics.file_many", "файлов")) }, "Не скопировано: {n} (лимит размера или нечитаемые)."))}</span></p>` : ""}
      ${IMP.truncated ? `<p class="fhint">${ic("alert")}<span>${esc(F.t("forensics.truncated", "Выбрано больше 500 файлов или 512 МБ. Разобраны будут первые в пределах лимита."))}</span></p>` : ""}
      <button class="btn text sm fx-clear" data-act="imp-clear">${ic("x")}${esc(F.t("forensics.clear_sel", "Очистить выбор"))}</button></div>`;
  }
  function impProgress() {
    const r = IMP.run;
    const pct = r.total ? Math.round((r.done / r.total) * 100) : 0;
    return `<div class="card pad fx-prog" role="status" aria-live="polite">
      <div class="fx-tlh"><b>${impProgressTitle(r)}</b><span class="muted">${esc(F.t("forensics.n_of", { i: r.done, n: r.total || "…" }, "{i} из {n}"))}</span></div>
      <div class="pbar"><i style="width:${pct}%"></i></div>
      <div class="fx-sub fx-break">${esc(r.name || "")}</div>
      <button class="btn block" data-act="imp-cancel" ${r.cancelling ? "disabled" : ""}>${ic("stop")}${r.cancelling ? F.t("forensics.cancelling", "Отменяется…") : F.t("common.cancel", "Отмена")}</button></div>`;
  }
  function impResult() {
    const x = IMP.result;
    if (x.error)
      return `<div class="banner bad">${ic("alert")}<div>${esc(F.t("forensics.parse_err", { e: x.error }, "Разбор не выполнен: {e}"))}</div></div>`;
    const sk = x.skipped || [],
      er = x.errors || [];
    return `<div class="card pad fx-res">
      <div class="fx-tlh"><b>${x.cancelled ? F.t("forensics.imp_cancelled", "Разбор отменён") : F.t("forensics.imp_done", "Разбор завершён")}</b>${x.cancelled ? pill("warn", F.t("forensics.cancelled", "Отменено")) : pill("ok", F.t("forensics.done", "Готово"), "check")}</div>
      <div class="kv fx-kv">${kvr(F.t("forensics.imp_added", "Добавлено документов"), String(x.imported || 0))}${x.duplicates ? kvr(F.t("forensics.imp_dup", "Уже были в проекте"), String(x.duplicates)) : ""}${sk.length ? kvr(F.t("forensics.imp_skipped", "Пропущено"), String(sk.length)) : ""}${er.length ? kvr(F.t("forensics.imp_errors", "Ошибки разбора"), String(er.length)) : ""}</div>
      ${sk.length || er.length ? `<details class="fx-sec"><summary><span class="fx-st">${esc(F.t("forensics.imp_notdone", "Что не разобрано"))}</span>${ic("chev-down", "fx-chev")}</summary><div class="fx-body"><ul class="fx-files">${sk.map(s => `<li><span class="fx-break">${esc(s.name)}</span>: ${esc(SKIP[s.reason] || s.reason)}</li>`).join("")}${er.map(s => `<li><span class="fx-break">${esc(s.name)}</span>: ${esc(ERR[s.error] || s.error)}</li>`).join("")}</ul></div></details>` : ""}
      <div class="btnrow fx-btns"><button class="btn primary" data-act="imp-open:${esc(x.project)}">${ic("open")}${esc(F.t("forensics.open_project", "Открыть проект"))}</button><button class="btn" data-act="imp-again">${esc(F.t("forensics.parse_more", "Разобрать ещё"))}</button></div></div>`;
  }
  // Built-in reference case (demo_case_import): twelve synthetic documents of the fictional
  // «ТОВ Приклад», imported by the core without network.
  // Project name the core gives the reference case (an identifier for "already imported", not UI text).
  const DEMO_CASE_NAME = "Эталонный кейс";
  const demoCaseName = () => F.t("forensics.demo_case_name", DEMO_CASE_NAME);
  const DEMO_CASE_N = 12;
  function demoCaseCard() {
    return `<div class="list fx-democase">${ui.row({
      lead: ui.leadIcon("spark", "var(--accent)"),
      title: F.t("forensics.demo_open", "Открыть эталонный кейс"),
      sub: F.tp(
        "forensics.demo_sub",
        DEMO_CASE_N,
        { n: DEMO_CASE_N },
        "{n} синтетический документ вымышленной ТОВ «Приклад» · без интернета|{n} синтетических документа вымышленной ТОВ «Приклад» · без интернета|{n} синтетических документов вымышленной ТОВ «Приклад» · без интернета",
      ),
      act: "demo-case",
    })}</div>`;
  }
  F.demoCaseCard = demoCaseCard;
  function impProgressTitle(r) {
    if (r.demo)
      return r.stage === "analysis"
        ? F.t("forensics.st_demo_an", "Анализ эталонного кейса")
        : F.t("forensics.st_demo_imp", "Импорт эталонного кейса");
    return r.stage === "analysis"
      ? F.t("forensics.st_an", "Анализ находок")
      : F.t("forensics.st_parse", "Разбор файлов");
  }
  function renderImport() {
    const cur = F.db.project;
    return `<div class="banner ok fx-offline">${ic("shield")}<div><b>${esc(F.t("forensics.no_net_t", "Без сети."))}</b> ${esc(F.t("forensics.no_net_d", "Файлы разбираются на телефоне и не покидают устройство. Приложение не делает ни одного запроса в интернет."))}</div></div>
      ${
        IMP.run
          ? impProgress()
          : IMP.result
            ? impResult()
            : `${demoCaseCard()}
      ${ui.secH(F.t("forensics.where_to", "Куда"))}
      <div class="seg fx-into" role="radiogroup" aria-label="${esc(F.t("forensics.where_aria", "Куда добавить документы"))}">
        <button class="${IMP.into === "new" ? "on" : ""}" role="radio" aria-checked="${IMP.into === "new"}" data-act="imp-into:new">${esc(F.t("forensics.new_project", "Новый проект"))}</button>
        <button class="${IMP.into === "cur" ? "on" : ""}" role="radio" aria-checked="${IMP.into === "cur"}" data-act="imp-into:cur"
          ${cur ? "" : "disabled"}>${cur ? esc(F.t("forensics.into_cur_n", { name: cur.name }, "В текущий «{name}»")) : esc(F.t("forensics.into_cur", "В текущий"))}</button></div>
      ${
        IMP.into === "new"
          ? `<label class="flabel" for="imp-name">${esc(F.t("forensics.project_name", "Название проекта"))}</label><div class="field">${ic("folder")}<input id="imp-name"
        value="${esc(IMP.name || defName())}" autocomplete="off" enterkeyhint="next"></div>
      <label class="flabel" for="imp-dom">${esc(F.t("forensics.org_domain", "Домен организации"))} <small>${esc(F.t("forensics.optional", "необязательно"))}</small></label><div class="field">${ic("domain")}<input id="imp-dom"
        value="${esc(IMP.domain)}" placeholder="example.com.ua" autocapitalize="off" spellcheck="false" enterkeyhint="done"></div>
      <p class="fhint">${ic("info")}<span>${esc(F.t("forensics.dom_note", "Домен нужен только для шаблона e-mail; сканирование не запускается."))}</span></p>`
          : ""
      }
      ${ui.secH(F.t("forensics.what", "Что разобрать"))}
      <div class="grid g2 fx-pick">
        <button class="card tap fx-pickb" data-act="imp-pick:folder">${ui.leadIcon("folder")}<span>${esc(F.t("forensics.pick_folder", "Выбрать папку"))}<small>${esc(F.t("forensics.pick_folder_sub", "со всеми вложенными"))}</small></span></button>
        <button class="card tap fx-pickb" data-act="imp-pick:files">${ui.leadIcon("doc")}<span>${esc(F.t("forensics.pick_files", "Файлы или ZIP"))}<small>${esc(F.t("forensics.pick_files_sub", "один или несколько"))}</small></span></button>
      </div>
      ${impPicked()}
      <p class="fhint">${ic("info")}<span>${esc(F.t("forensics.limits", "До 500 файлов и 512 МБ за раз, файл: до 100 МБ; ZIP распаковывается в памяти (вложенные архивы, до 2 уровней)."))}</span>${F.helpBtn ? F.helpBtn("offline-help", F.t("forensics.offline", "Офлайн-разбор")) : ""}</p>
      <button class="btn primary block fx-go" data-act="imp-start" ${IMP.files.length ? "" : "disabled"}>${ic("play")}${IMP.files.length ? F.t("forensics.parse_n", { n: plural(IMP.files.length, F.t("forensics.file_one", "файл"), F.t("forensics.file_few", "файла"), F.t("forensics.file_many", "файлов")) }, "Разобрать {n}") : F.t("forensics.pick_files_none", "Выберите файлы")}</button>`
      }`;
  }
  const impRender = () => {
    if (F.cur && F.cur.path === "/import") F.render(true);
  };
  const readForm = () => {
    const pg = F.page();
    if (!pg) return;
    const n = pg.querySelector("#imp-name"),
      d = pg.querySelector("#imp-dom");
    if (n) IMP.name = n.value.trim();
    if (d) IMP.domain = d.value.trim();
  };
  F.on("scan", ev => {
    if (ev.type !== "import" || !IMP.run) return;
    Object.assign(IMP.run, {
      done: ev.done || 0,
      total: ev.total || IMP.run.total,
      stage: ev.stage,
      name: ev.name,
    });
    const box = F.page() && F.page().querySelector(".fx-prog");
    if (box && F.cur && F.cur.path === "/import") box.outerHTML = impProgress();
  });
  // Reference case finished: open the new project right away (the result card stays as a fallback).
  function finishDemoCase(res) {
    finishImport(res);
    if (!res || res.error || !res.project || res.cancelled) return;
    IMP.result = null;
    F.api.project_open(res.project).then(
      () => {
        F.reset(["/projects", "/p/overview"]);
        F.snack(
          F.t(
            "forensics.demo_opened",
            {
              n: plural(
                res.imported || 0,
                F.t("forensics.doc_one", "документ"),
                F.t("forensics.doc_few", "документа"),
                F.t("forensics.doc_many", "документов"),
              ),
            },
            "Эталонный кейс открыт: {n}",
          ),
        );
      },
      e =>
        F.snack(F.t("forensics.open_fail", { e: (e && e.message) || e }, "Не удалось открыть проект: {e}")),
    );
  }
  function finishImport(res) {
    IMP.run = null;
    IMP.result = res;
    IMP.files = [];
    F.api.platform_pick_clear().catch(() => {});
    if (res && res.project && !res.error) F.api.project_list().catch(() => {});
    impRender();
  }
  Object.assign(F.actions, {
    "imp-into": v => {
      readForm();
      IMP.into = v;
      impRender();
    },
    "imp-pick": kind => {
      readForm();
      const p =
        kind === "folder" ? F.api.platform_pick_folder({}) : F.api.platform_pick_files({ multiple: true });
      p.then(
        r => {
          if (!r || r.cancelled || !(r.files || []).length) return;
          IMP.files = r.files;
          IMP.skipped = typeof r.skipped === "number" ? r.skipped : (r.skipped || []).length;
          IMP.truncated = !!r.truncated;
          IMP.bytes = r.bytes || r.files.reduce((s, f) => s + (f.size || 0), 0);
          impRender();
        },
        e =>
          F.snack(
            e && e.code === "unsupported"
              ? F.t("forensics.folder_android", "Выбор папки доступен в приложении на Android")
              : F.t("forensics.pick_fail", { e: (e && e.message) || e }, "Не удалось выбрать файлы: {e}"),
          ),
      );
    },
    "imp-clear": () => {
      IMP.files = [];
      F.api.platform_pick_clear().catch(() => {});
      impRender();
    },
    "imp-start": () => {
      readForm();
      if (!IMP.files.length) return;
      const args = { paths: IMP.files.map(f => f.path) };
      if (IMP.into === "cur" && F.db.project) args.project = F.db.project.id;
      else {
        args.name = IMP.name || defName();
        if (IMP.domain) args.domain = IMP.domain;
      }
      IMP.run = { done: 0, total: IMP.files.length, stage: "parse", name: "", cancelled: false };
      impRender();
      if (F.isDemo) {
        // The demo backend is synchronous: show the progress file by file, then import.
        const run = IMP.run;
        let i = 0;
        const tick = () => {
          if (IMP.run !== run) return;
          if (run.cancelled)
            return finishImport({
              project: args.project || null,
              imported: 0,
              duplicates: 0,
              skipped: [],
              errors: [],
              cancelled: true,
            });
          if (i < IMP.files.length) {
            Object.assign(run, { done: i, name: IMP.files[i].name, stage: "parse" });
            i++;
            const box = F.page() && F.page().querySelector(".fx-prog");
            if (box) box.outerHTML = impProgress();
            return setTimeout(tick, 220);
          }
          F.api.import_offline(args).then(finishImport, e => finishImport({ error: e.message || String(e) }));
        };
        setTimeout(tick, 120);
        return;
      }
      F.api.import_offline(args).then(finishImport, e => finishImport({ error: e.message || String(e) }));
    },
    "imp-cancel": () => {
      if (!IMP.run) return;
      IMP.run.cancelled = IMP.run.cancelling = true;
      const box = F.page() && F.page().querySelector(".fx-prog");
      if (box) box.outerHTML = impProgress();
      if (!F.isDemo) F.api.import_cancel().catch(() => {});
    },
    "demo-case": () => {
      if (IMP.run) {
        F.go("/import");
        return;
      }
      // The case may have been created in another UI language.
      const names = [DEMO_CASE_NAME, "Еталонний кейс", "Reference case", demoCaseName()];
      const have = (F.projects || []).find(p => (p.reference || names.includes(p.name)) && !p.archived);
      if (have) {
        F.sheet({
          title: F.t("forensics.demo_exists", "Эталонный кейс уже есть"),
          html: `<p class="lead">${esc(F.t("forensics.demo_exists_t", { name: have.name }, "Проект «{name}» уже создан. Открыть его или импортировать кейс заново в новый проект?"))}</p>`,
          footer: `<button class="btn" data-act="demo-case-new">${esc(F.t("forensics.reimport", "Импортировать заново"))}</button><button class="btn primary"
            data-act="imp-open:${esc(have.id)}">${ic("open")}${esc(F.t("common.open", "Открыть"))}</button>`,
        });
        return;
      }
      F.actions["demo-case-new"]();
    },
    "demo-case-new": () => {
      if (F.closeSheet) F.closeSheet();
      IMP.result = null;
      IMP.run = { done: 0, total: DEMO_CASE_N, stage: "parse", name: "", cancelled: false, demo: true };
      if (!F.cur || F.cur.path !== "/import") F.go("/import");
      else impRender();
      const run = IMP.run;
      const call = () =>
        F.api
          .demo_case_import({ name: demoCaseName() })
          .then(finishDemoCase, e => finishImport({ error: (e && e.message) || String(e) }));
      if (!F.isDemo) return call();
      // The demo backend is synchronous: show the progress file by file, then import.
      let i = 0;
      const tick = () => {
        if (IMP.run !== run) return;
        if (run.cancelled)
          return finishImport({
            project: null,
            imported: 0,
            duplicates: 0,
            skipped: [],
            errors: [],
            cancelled: true,
          });
        if (i < DEMO_CASE_N) {
          Object.assign(run, { done: i, name: `Приклад · документ ${i + 1}`, stage: "parse" });
          i++;
          const box = F.page() && F.page().querySelector(".fx-prog");
          if (box) box.outerHTML = impProgress();
          return setTimeout(tick, 90);
        }
        call();
      };
      setTimeout(tick, 120);
    },
    "imp-open": id => {
      if (F.closeSheet) F.closeSheet();
      if (!id || id === "null") return;
      IMP.result = null;
      F.api.project_open(id).then(() => F.reset(["/projects", "/p/overview"]));
    },
    "imp-again": () => {
      IMP.result = null;
      impRender();
    },
  });
  F.route("/import", {
    title: () => F.t("forensics.offline_title", "Разбор файлов без сети"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: renderImport,
  });

  // ================= search rules /p/rules =================
  const RS = (F.state.rules = F.state.rules || {
    pid: null,
    data: null,
    cfg: null,
    err: {},
    test: {},
    open: {},
  });
  const SEVS = tt(
    "forensics.sev",
    [
      ["low", "Низкая"],
      ["warn", "Средняя"],
      ["high", "Высокая"],
      ["crit", "Критичная"],
    ],
    1,
  );
  const newId = () => "r" + Date.now().toString(36) + Math.floor(Math.random() * 1e4).toString(36);
  function loadRules() {
    const pid = (F.db.project || {}).id;
    if (RS.pid === pid && RS.data) return;
    RS.pid = pid;
    RS.data = null;
    F.api.rules_get().then(
      r => {
        RS.data = r;
        RS.cfg = JSON.parse(JSON.stringify(r.config || { presets: [], rules: [] }));
        RS.err = {};
        if (F.cur && F.cur.path === "/p/rules") F.render(true);
      },
      e => {
        RS.data = { error: e.message || String(e) };
        if (F.cur && F.cur.path === "/p/rules") F.render(true);
      },
    );
  }
  /** Highlights byte ranges (UTF-8 offsets from the core) in the sample text, escaping everything else. */
  function markBytes(text, hits) {
    const bytes = new TextEncoder().encode(text);
    const dec = new TextDecoder();
    let out = "",
      pos = 0;
    hits
      .slice()
      .sort((a, b) => a.start - b.start)
      .forEach(h => {
        if (h.start < pos || h.end > bytes.length) return;
        out += esc(dec.decode(bytes.slice(pos, h.start)));
        out += `<mark class="fx-hl">${esc(dec.decode(bytes.slice(h.start, h.end)))}</mark>`;
        pos = h.end;
      });
    return out + esc(dec.decode(bytes.slice(pos)));
  }
  function ruleCard(r, i) {
    const t = RS.test[r.id] || {};
    const err = RS.err[r.id];
    return `<div class="card pad fx-rule ${err ? "bad" : ""}" data-rule="${esc(r.id)}">
      <div class="fx-rtop"><label class="sr-only" for="rt-${i}">${esc(F.t("forensics.rule_name", "Название правила"))}</label><div class="field fx-rtitle"><input id="rt-${i}"
        data-rf="title" value="${esc(r.title)}" placeholder="${esc(F.t("forensics.rule_ph", "Название, например «Номер договору»"))}" autocomplete="off"></div>
        ${ui.toggle(r.enabled !== false, `rule-on:${esc(r.id)}`, `aria-label="${esc(F.t("forensics.rule_on", { name: r.title || F.t("forensics.untitled", "без названия") }, "Правило включено: {name}"))}"`)}</div>
      <label class="flabel" for="rp-${i}">${esc(F.t("forensics.regex", "Регулярное выражение"))}</label><div class="field fx-rpat"><input id="rp-${i}" class="mono"
        data-rf="pattern" value="${esc(r.pattern)}" placeholder="договір\\s*№\\s*(?P&lt;v&gt;[\\d/-]+)" autocapitalize="off"
        autocomplete="off" spellcheck="false" aria-describedby="re-${i}"></div>
      <div id="re-${i}" class="fx-err" role="alert">${err ? `${ic("alert")}${esc(err)}` : ""}</div>
      <div class="seg fx-rsev" role="radiogroup" aria-label="${esc(F.t("forensics.rule_sev", "Важность находки"))}">${SEVS.map(([k, l]) => `<button class="${r.sev === k ? "on" : ""}" role="radio" aria-checked="${r.sev === k}" data-act="rule-sev:${esc(r.id)}:${k}">${l}</button>`).join("")}</div>
      <div class="fx-rchecks">${ui.check(r.case_insensitive !== false, F.t("forensics.ci", "Без учёта регистра"), `rule-ci:${esc(r.id)}`)}${ui.check(r.mask !== false, F.t("forensics.mask", "Маскировать найденное значение"), `rule-mask:${esc(r.id)}`, F.t("forensics.mask_sub", "в находке видны только последние символы"))}</div>
      <details class="fx-sec fx-rtest" ${RS.open[r.id] ? "open" : ""} data-rt="${esc(r.id)}"><summary><span class="fx-st">${esc(F.t("forensics.test_on", "Проверить на тексте"))}</span>${ic("chev-down", "fx-chev")}</summary><div class="fx-body">
        <label class="sr-only" for="rx-${i}">${esc(F.t("forensics.sample", "Пример текста"))}</label><textarea id="rx-${i}" class="fx-rta" data-rf="sample" rows="3"
          placeholder="${esc(F.t("forensics.sample_ph", "Вставьте фрагмент документа"))}">${esc(t.sample || "")}</textarea>
        <button class="btn tonal" data-act="rule-test:${esc(r.id)}">${ic("search")}${esc(F.t("forensics.check", "Проверить"))}</button>
        <div class="fx-tres" aria-live="polite">${t.error ? `<div class="fx-err">${ic("alert")}${esc(t.error)}</div>` : t.res ? `<div class="fx-cnt">${t.res.count ? F.t("forensics.matches_n", { n: t.res.count }, "Совпадений: {n}") : F.t("forensics.no_matches", "Совпадений нет")}</div>${t.res.count ? `<div class="fx-sample fx-break">${markBytes(t.sample || "", t.res.hits)}</div><div class="fhint">${ic("lock")}<span>${esc(F.t("forensics.values", "Значения:"))} ${t.res.hits.map(h => esc(h.value)).join(", ")}</span></div>` : ""}` : ""}</div>
      </div></details>
      <button class="btn text sm fx-rdel" data-act="rule-del:${esc(r.id)}">${ic("trash")}${esc(F.t("forensics.rule_del", "Удалить правило"))}</button></div>`;
  }
  function renderRules() {
    loadRules();
    if (!RS.data) return ui.skeletonCards(3);
    if (RS.data.error)
      return ui.error({
        title: F.t("forensics.rules_fail", "Не удалось загрузить правила"),
        text: RS.data.error,
        retry: "rules-reload",
      });
    const cfg = RS.cfg;
    const presets = RS.data.presets || [];
    const gen = RS.err._;
    return `<p class="lead fx-lead">${esc(F.t("forensics.rules_lead", "Правила ищут совпадения в тексте документов проекта. После сохранения находки пересчитываются сразу. Повторный скан не нужен."))}</p>
      ${ui.secH(F.t("forensics.presets", "Готовые наборы"), "", F.helpBtn ? F.helpBtn("rules-help", F.t("forensics.rules_help", "Правила поиска")) : "")}
      <div class="list fx-presets">${presets
        .map(p => {
          const on = cfg.presets.includes(p.id);
          // Preset texts come from the core in Russian: render them by preset and rule id.
          const title = F.t(`forensics.preset_title_${p.id}`, p.title);
          const desc = p.description ? F.t(`forensics.preset_desc_${p.id}`, p.description) : "";
          return `<div class="row fx-preset"><div class="body"><div class="t">${esc(title)}</div><div class="s">${esc(desc)}</div>
            <details class="fx-pd"><summary>${plural((p.rules || []).length, F.t("forensics.rule_one", "правило"), F.t("forensics.rule_few", "правила"), F.t("forensics.rule_many", "правил"))}</summary><ul class="fx-files">${(p.rules || []).map(x => `<li>${esc(F.t(`forensics.preset_rule_${x.id}`, x.title))} ${ui.sev(x.sev)}</li>`).join("")}</ul></details></div>
            ${ui.toggle(on, `rule-preset:${esc(p.id)}`, `aria-label="${esc(F.t("forensics.preset_aria", { name: title }, "Набор «{name}»"))}"`)}</div>`;
        })
        .join("")}</div>
      ${ui.secH(F.t("forensics.own_rules", "Свои правила"), cfg.rules.length || "")}
      ${cfg.rules.length ? cfg.rules.map(ruleCard).join("") : `<p class="la-none">${esc(F.t("forensics.no_rules", "Своих правил нет. Например, номер договора, инвентарный номер или внутренний код проекта."))}</p>`}
      <button class="btn block fx-radd" data-act="rule-add" ${cfg.rules.length >= 64 ? "disabled" : ""}>${ic("plus")}${esc(F.t("forensics.rule_add", "Добавить правило"))}</button>
      ${gen ? `<div class="banner bad">${ic("alert")}<div>${esc(gen)}</div></div>` : ""}
      <p class="fhint">${ic("info")}<span>${esc(F.t("forensics.group_note1", "Группа"))} <code>(?P&lt;v&gt;…)</code> ${esc(F.t("forensics.group_note2", "задаёт значение, которое попадёт в находку. Шаблон: до 512 символов, не больше 64 правил; шаблоны, совпадающие с пустой строкой, не принимаются."))}</span></p>
      <button class="btn primary block fx-rsave" data-act="rules-save">${ic("save")}${esc(F.t("forensics.save_recalc", "Сохранить и пересчитать"))}</button>`;
  }
  /** Copies the typed values of the rule cards into RS.cfg (inputs are not re-rendered while typing). */
  function readRules() {
    const pg = F.page();
    if (!pg || !RS.cfg) return;
    pg.querySelectorAll(".fx-rule").forEach(card => {
      const r = RS.cfg.rules.find(x => x.id === card.dataset.rule);
      if (!r) return;
      card.querySelectorAll("[data-rf]").forEach(inp => {
        if (inp.dataset.rf === "sample") (RS.test[r.id] = RS.test[r.id] || {}).sample = inp.value;
        else r[inp.dataset.rf] = inp.value;
      });
    });
  }
  const ruleOf = id => RS.cfg.rules.find(x => x.id === id);
  const rulesRender = () => {
    if (F.cur && F.cur.path === "/p/rules") F.render(true);
  };
  /** Splits a core error "user:<id>: message; …" per rule card; the rest is a general error. */
  function applyErrors(msg) {
    RS.err = {};
    String(msg)
      .split(/;\s*/)
      .forEach(part => {
        const m = /^user:([^:]+):\s*(.*)$/.exec(part);
        if (m && ruleOf(m[1])) RS.err[m[1]] = m[2];
        else
          RS.err._ =
            (RS.err._ ? RS.err._ + "; " : "") +
            part.replace(/^preset:/, F.t("forensics.preset_pfx", "набор "));
      });
  }
  Object.assign(F.actions, {
    "rules-reload": () => {
      RS.data = null;
      RS.pid = null;
      F.render(true);
    },
    "rule-preset": (id, el) => {
      readRules();
      const a = RS.cfg.presets;
      a.includes(id) ? a.splice(a.indexOf(id), 1) : a.push(id);
      el.classList.toggle("on", a.includes(id));
      el.setAttribute("aria-checked", a.includes(id));
    },
    "rule-add": () => {
      readRules();
      RS.cfg.rules.push({
        id: newId(),
        title: "",
        pattern: "",
        sev: "warn",
        enabled: true,
        case_insensitive: true,
        mask: true,
      });
      rulesRender();
      setTimeout(() => {
        const ins = F.page() && F.page().querySelectorAll(".fx-rtitle input");
        if (ins && ins.length) ins[ins.length - 1].focus();
      }, 50);
    },
    "rule-del": id => {
      readRules();
      const i = RS.cfg.rules.findIndex(x => x.id === id);
      if (i < 0) return;
      const [gone] = RS.cfg.rules.splice(i, 1);
      delete RS.err[id];
      rulesRender();
      F.snack(F.t("forensics.rule_deleted", "Правило удалено: сохраните, чтобы применить"), {
        action: () => {
          RS.cfg.rules.splice(i, 0, gone);
          rulesRender();
        },
      });
    },
    "rule-on": (id, el) => {
      readRules();
      const r = ruleOf(id);
      r.enabled = r.enabled === false;
      el.classList.toggle("on", r.enabled);
      el.setAttribute("aria-checked", r.enabled);
    },
    "rule-ci": (id, el) => {
      readRules();
      const r = ruleOf(id);
      r.case_insensitive = r.case_insensitive === false;
      el.classList.toggle("on", r.case_insensitive);
      el.setAttribute("aria-checked", r.case_insensitive);
    },
    "rule-mask": (id, el) => {
      readRules();
      const r = ruleOf(id);
      r.mask = r.mask === false;
      el.classList.toggle("on", r.mask);
      el.setAttribute("aria-checked", r.mask);
    },
    "rule-sev": arg => {
      readRules();
      const [id, sev] = arg.split(":");
      ruleOf(id).sev = sev;
      rulesRender();
    },
    "rule-test": id => {
      readRules();
      const r = ruleOf(id),
        t = (RS.test[id] = RS.test[id] || {});
      RS.open[id] = true;
      if (!String(r.pattern || "").trim()) {
        t.error = F.t("forensics.enter_regex", "Введите регулярное выражение");
        t.res = null;
        return rulesRender();
      }
      if (!String(t.sample || "").trim()) {
        t.error = F.t("forensics.enter_sample", "Вставьте пример текста");
        t.res = null;
        return rulesRender();
      }
      F.api.rules_test(r.pattern, t.sample, r.case_insensitive !== false).then(
        res => {
          t.res = res;
          t.error = "";
          rulesRender();
        },
        e => {
          t.res = null;
          t.error = e.message || String(e);
          rulesRender();
        },
      );
    },
    "rules-save": () => {
      readRules();
      const empty = RS.cfg.rules.find(r => !String(r.pattern || "").trim());
      if (empty) {
        RS.err = {
          [empty.id]: F.t("forensics.regex_or_del", "Введите регулярное выражение или удалите правило"),
        };
        return rulesRender();
      }
      RS.cfg.rules.forEach(r => {
        if (!String(r.title || "").trim()) r.title = r.pattern.slice(0, 40);
      });
      F.api.rules_set(RS.cfg).then(
        res => {
          RS.cfg = JSON.parse(JSON.stringify(res.config || RS.cfg));
          RS.err = {};
          if (F.api.reload) F.api.reload("findings");
          rulesRender();
          F.snack(
            res.new_findings
              ? F.t("forensics.saved_new", { n: res.new_findings }, "Правила сохранены · новых находок: {n}")
              : F.t("forensics.saved_none", "Правила сохранены · новых находок нет"),
          );
        },
        e => {
          applyErrors(e.message || String(e));
          rulesRender();
          F.snack(F.t("forensics.rules_unsaved", "Правила не сохранены: исправьте ошибки"));
        },
      );
    },
  });
  F.route("/p/rules", {
    title: () => F.t("forensics.rules_help", "Правила поиска"),
    sub: () => (F.project ? F.project.name : ""),
    back: true,
    tab: "overview",
    actions: [],
    hideMini: true,
    render: () => F.withStates(renderRules, { loading: "cards" }),
    mount: page => {
      page.addEventListener(
        "toggle",
        e => {
          const d = e.target.closest && e.target.closest(".fx-rtest");
          if (d) RS.open[d.dataset.rt] = d.open;
        },
        true,
      );
      page.addEventListener("input", e => {
        const card = e.target.closest(".fx-rule");
        if (card && e.target.dataset.rf === "pattern" && RS.err[card.dataset.rule]) {
          delete RS.err[card.dataset.rule];
          card.classList.remove("bad");
          const box = card.querySelector(".fx-err");
          if (box) box.textContent = "";
        }
      });
    },
  });

  F.fx = { CODE, CODE_HELP, snippet, docBlocks, mountDoc, globalText, maskedLabel };
})();
