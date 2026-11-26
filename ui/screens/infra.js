// Infrastructure data of the infrastructure modules (infra_get, docs/API.md → "Инфраструктура").
// Data segments /p/data/certs (certificates + audit, CT history), /p/data/mailpol (mail policies),
// /p/data/saas (SaaS, Microsoft 365 tenant, CDN/clouds, origin and out-of-scope candidates), plus labels
// and blocks reused by other screens: host roles/sources/CDN (data.js), the certificate block of the host
// card, finding code notes (findings.js) and out-of-scope sources (scan.js). Exported as F.infra.
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  const enc = encodeURIComponent;
  // Label tables keep Russian fallbacks; values are translated on read with the key "<prefix>.<key>".
  const tt = (prefix, table) =>
    new Proxy(table, {
      get: (o, k) => {
        const v = o[k];
        if (typeof k !== "string" || !Object.prototype.hasOwnProperty.call(o, k)) return v;
        return Array.isArray(v) ? [F.t(`${prefix}.${k}`, v[0]), ...v.slice(1)] : F.t(`${prefix}.${k}`, v);
      },
    });

  // ---------- labels (Russian fallbacks, translated through tt) ----------
  const ROLE = tt("infra.role", {
    dev_stage: "Тест / стейдж",
    remote_access: "Удалённый доступ",
    admin: "Админка",
    api: "API",
    vcs_ci: "Код и CI",
    mail: "Почта",
    monitoring: "Мониторинг",
    database: "База данных",
    storage: "Файлы",
    auth: "Вход (SSO)",
    internal: "Внутренний",
  });
  const HOST_SRC = tt("infra.src", {
    bruteforce: "Перебор поддоменов",
    permute: "Перестановки имён",
    ptr: "Обратная зона (PTR)",
    nsec: "Обход зоны (NSEC)",
    tls_san: "SAN сертификата",
    m365: "Арендатор Microsoft 365",
  });
  const CT_SRC = /^(crt\.sh|crt|ct)$/i;
  const SAAS_CAT = tt("infra.saas_cat", {
    email: "Почта",
    productivity: "Офис и почта",
    collaboration: "Совместная работа",
    identity: "Учётные записи",
    dev: "Разработка",
    crm: "CRM",
    marketing: "Маркетинг и рассылки",
    payments: "Платежи",
    security: "Безопасность",
    cloud: "Облака",
    docs: "Документы и подписи",
    support: "Поддержка",
    analytics: "Аналитика",
    ai: "ИИ-сервисы",
  });
  const EVIDENCE = { txt: "TXT", spf_include: "SPF include", mx: "MX", cname: "CNAME" };
  const OOS_SRC = tt("infra.oos_src", {
    san: "SAN сертификата",
    org_pivot: "Та же организация (O=)",
    tenant_domain: "Домен арендатора M365",
    origin_ip: "Исходный IP за CDN",
    ptr: "PTR-имя",
    federation: "Хост AD FS",
    csp: "Домен из CSP сайта",
  });
  const TRUST = tt("infra.trust", {
    trusted: ["Доверенный", "ok"],
    self_signed: ["Самоподписанный", "bad"],
    unknown_ca: ["Неизвестный УЦ", "warn"],
    incomplete_chain: ["Неполная цепочка", "warn"],
    invalid: ["Недействителен", "bad"],
  });
  const MODE = tt("infra.mode", {
    tls: "TLS",
    starttls: "STARTTLS",
    no_sni: "по IP без SNI",
    legacy: "устаревшие версии",
  });
  const ORIGIN_REASON = tt("infra.origin_reason", {
    origin_label: "имя похоже на исходный сервер",
    subdomain: "адрес поддомена",
    historical: "исторический адрес",
    mx: "почтовый сервер (MX)",
    spf: "адрес из SPF",
    other: "другой источник",
    multi_source: "подтверждён несколькими источниками",
    hosting_range: "сеть хостинга",
    same_net: "в одной сети с другими кандидатами",
  });
  const DNSSEC = tt("infra.dnssec", {
    signed: ["Подписана", "ok"],
    unanchored: ["Подписана без DS у родителя", "warn"],
    unsigned: ["Не подписана", "warn"],
    unknown: ["Не определено", "mute"],
  });
  // What a finding code means, in one line (finding card; the core sends title/description/recommendation).
  const CODE = tt("infra.code", {
    cert_expired:
      "Срок сертификата истёк: браузеры показывают ошибку, и пользователи привыкают её пропускать.",
    cert_expires_soon: "Сертификат скоро истечёт: проверьте автопродление.",
    cert_not_yet_valid: "Сертификат ещё не начал действовать. Обычно сбито время на сервере.",
    cert_self_signed: "Самоподписанный сертификат: подлинность сервера проверить нельзя, возможен перехват.",
    cert_unknown_ca: "Сертификат выдан УЦ, которого нет среди доверенных (часто внутренний УЦ компании).",
    cert_invalid_chain: "Цепочка сертификатов не проверяется, клиенты увидят ошибку.",
    cert_incomplete_chain:
      "Сервер не отдаёт промежуточный сертификат. Часть клиентов (Android, curl) не подключится.",
    cert_hostname_mismatch: "Имя в сертификате не совпадает с адресом. Чужой или стандартный сертификат.",
    cert_weak_signature: "Подпись SHA-1 или MD5. Устаревший алгоритм, подделка возможна.",
    cert_weak_key: "Ключ RSA короче 2048 бит, недостаточная стойкость.",
    cert_caa_mismatch: "Сертификат выпустил УЦ, которого нет в CAA-записях домена.",
    cert_internal_pki: "В сертификате видны внутренние адреса PKI или домен Active Directory.",
    tls_no_ocsp_stapling: "Сервер не прикладывает ответ OCSP. Проверка отзыва медленнее и идёт через УЦ.",
    tls_no_alpn: "Нет ALPN: HTTP/2 не используется; на безопасность почти не влияет.",
    tls_legacy_version: "Включены TLS 1.0/1.1: устаревшие версии с известными атаками.",
    tls_weak_cipher: "Сервер принимает слабые шифры (RC4, 3DES, EXPORT, NULL).",
    tls_origin_confirmed: "Сервер за CDN отвечает напрямую по IP. Защиту CDN можно обойти.",
    tls_default_cert: "По IP без имени отдаётся сертификат по умолчанию. Он раскрывает другие сайты сервера.",
    dns_wildcard: "Зона отвечает на любые имена (wildcard), ложные хосты отфильтрованы.",
    dns_resolver_hijack: "Резолвер сети подменяет ответы. Часть найденных имён не подтверждена.",
    nsec_walkable: "Зона подписана NSEC без NSEC3. Список всех имён можно получить обходом.",
    ptr_shared_hosting: "На адресе много чужих сайтов (общий хостинг). Проверки по IP не проводились.",
    ptr_fcrdns_mismatch: "Обратная и прямая зоны не совпадают (FCrDNS), проверьте актуальность записей.",
    saas_inventory: "По DNS-записям видны облачные сервисы организации. Материал для фишинга и разведки.",
    m365_tenant: "У организации есть арендатор Microsoft 365: виден его идентификатор и регион.",
    m365_federated_adfs:
      "Вход в Microsoft 365 идёт через AD FS организации. Внешняя точка для подбора паролей.",
    origin_exposed: "Найден вероятный исходный адрес сайта за CDN. Кандидат, владельцу стоит проверить.",
    ct_abandoned_subdomain:
      "Сертификаты для имени перестали продлевать. Забытый хост или риск захвата поддомена.",
    host_role_exposed: "Служебный хост (тест, админка, CI, база) доступен из интернета.",
  });
  const EMPTY = {
    saas: [],
    tenant: [],
    mail_policy: [],
    cert: [],
    ct: [],
    cdn: [],
    origin: [],
    role: [],
    ptr: [],
    dns_enum: [],
    oos: [],
  };
  const data = () => (F.db && F.db.infra) || EMPTY;
  const plural = (n, a, b, c) => F.plural(n, a, b, c); // language-aware (1/other in English)
  const dmy = d =>
    String(d || "")
      .slice(0, 10)
      .split("-")
      .reverse()
      .join(".");
  // Certificate dates: epoch seconds from the core; ISO dates in the legacy host summary.
  const dateOf = v =>
    typeof v === "number" ? new Date(v * 1000).toISOString().slice(0, 10) : String(v || "");
  const kvr = (k, v) => `<div class="kvr"><div class="k">${k}</div><div class="v">${v}</div></div>`;
  // `title` (plain text) repeats the label for pills that can be cut with an ellipsis.
  const pill = (cls, text, icon, title) =>
    `<span class="pill ${cls}"${title ? ` title="${esc(title)}"` : ""}>${icon ? ic(icon) : ""}${text}</span>`;
  const daysText = n =>
    n == null
      ? ""
      : n < 0
        ? F.t("infra.days_expired", "истёк")
        : F.t(
            "infra.days_in",
            {
              n: plural(
                n,
                F.t("infra.day_one", "день"),
                F.t("infra.day_few", "дня"),
                F.t("infra.day_many", "дней"),
              ),
            },
            "через {n}",
          );

  // ---------- hosts: roles, source, CDN ----------
  /** Label of a host source; machine ids of the enumeration modules get a readable name. */
  function srcLabel(s) {
    const v = String(s || "");
    if (/^doc_token:/.test(v))
      return F.t("infra.doc_meta", { name: v.slice(10) }, "Метаданные документа «{name}»");
    return HOST_SRC[v] || v;
  }
  /** True for sources of the discovery modules (shown as a provenance pill). */
  const isEnumSrc = s => /^doc_token:/.test(String(s || "")) || !!HOST_SRC[s];
  const roleChips = h => (h.roles || []).map(r => pill("vio dt-role", esc(ROLE[r] || r))).join("");
  const priorityPill = h =>
    (h.priority || 0) >= 30
      ? pill("warn if-prio", F.t("infra.priority", { n: h.priority }, "Приоритет {n}"), "flag")
      : "";
  const cdnPill = h => {
    if (!h.cdn) return "";
    const kind =
      h.cdn.kind === "cdn"
        ? "CDN"
        : h.cdn.kind === "cloud"
          ? F.t("infra.cloud", "Облако")
          : F.t("infra.hosting", "Хостинг");
    const label = `${kind} · ${h.cdn.name || h.cdn.provider}`;
    return pill("mute if-cdn", esc(label), "globe", label);
  };
  const srcPill = h =>
    isEnumSrc(h.source)
      ? pill(
          "info if-src",
          esc(srcLabel(h.source)),
          CT_SRC.test(h.source) ? "lock" : "search",
          srcLabel(h.source),
        )
      : "";

  // ---------- certificates ----------
  const certsOf = host => data().cert.filter(c => c.host === host);
  const issueSev = i => i.severity || i.sev || "info";
  const SEV_RANK = { crit: 0, high: 1, warn: 2, low: 3, info: 4 };
  const worst = list =>
    list.reduce((m, i) => ((SEV_RANK[issueSev(i)] ?? 9) < (SEV_RANK[m] ?? 9) ? issueSev(i) : m), "ok");
  const trustPill = c => {
    const [t, cls] = TRUST[(c.trust || {}).status] || [F.t("infra.not_checked", "Не проверялся"), "mute"];
    return pill(cls, t, cls === "ok" ? "check" : "alert");
  };
  const issuePills = c =>
    (c.issues || [])
      .map(
        i =>
          `<span class="pill ${SEV_CLS[issueSev(i)] || "mute"}" title="${esc(CODE[i.code] || i.detail || "")}">${esc(CODE_SHORT[i.code] || i.code)}</span>`,
      )
      .join("");
  const SEV_CLS = { crit: "bad", high: "bad", warn: "warn", low: "info", info: "mute" };
  const CODE_SHORT = tt("infra.code_short", {
    cert_expired: "Истёк",
    cert_expires_soon: "Скоро истекает",
    cert_not_yet_valid: "Ещё не действует",
    cert_self_signed: "Самоподписанный",
    cert_unknown_ca: "Неизвестный УЦ",
    cert_invalid_chain: "Ошибка цепочки",
    cert_incomplete_chain: "Неполная цепочка",
    cert_hostname_mismatch: "Чужое имя",
    cert_weak_signature: "Слабая подпись",
    cert_weak_key: "Короткий ключ",
    cert_caa_mismatch: "Не по CAA",
    cert_internal_pki: "Внутренняя PKI",
    tls_no_ocsp_stapling: "Без OCSP stapling",
    tls_no_alpn: "Без ALPN",
    tls_legacy_version: "TLS 1.0/1.1",
    tls_weak_cipher: "Слабые шифры",
    tls_origin_confirmed: "Origin доступен",
    tls_default_cert: "Сертификат по умолчанию",
  });
  const leafOf = c => (c.chain || [])[0] || null;
  const shortFp = v => (v ? `${String(v).slice(0, 16)}…` : "-");

  /** Certificate block of the host card: one card per inspected port/mode. */
  function certBlock(host) {
    const list = certsOf(host);
    if (!list.length) return "";
    return (
      ui.secH(F.t("infra.cert_tls", "Сертификат TLS"), list.length > 1 ? list.length : "") +
      list
        .map(c => {
          const l = leafOf(c) || { subject: {}, issuer: {}, san_dns: [] };
          const left = c.days_left;
          const till = `${dmy(dateOf(l.not_after))}${left != null && left <= 30 ? ` · ${daysText(left)}` : ""}`;
          const pki = (c.pki || []).filter(x => x.internal || x.ad_domain);
          const leg = c.legacy || null;
          return `<div class="kv if-cert">${kvr(F.t("infra.port", "Порт"), `<span class="mono">${esc(String(c.port))}</span> · ${esc(MODE[c.mode] || c.mode)}${c.version ? ` · ${esc(String(c.version).replace("_", "."))}` : ""}`)}${kvr(F.t("infra.subject", "Субъект"), `<span class="mono">${esc(l.subject.text || (l.subject.cn ? "CN=" + l.subject.cn : "-"))}</span>`)}${kvr(F.t("infra.issuer", "Издатель"), esc(l.issuer.cn || l.issuer.text || "-"))}${kvr(F.t("infra.valid_until", "Действует до"), left != null && left <= 30 ? `<span class="dt-warn">${ic("alert")}${esc(till)}</span>` : esc(till))}${(l.san_dns || []).length ? kvr("SAN", `<span class="mono">${esc(l.san_dns.join(", "))}</span>`) : ""}${kvr(F.t("infra.trust_label", "Доверие"), `<div class="dt-tags">${trustPill(c)}${c.hostname_match === false ? pill("bad", F.t("infra.name_mismatch", "Имя не совпадает"), "alert") : ""}${issuePills(c)}</div>`)}${c.cipher ? kvr(F.t("infra.cipher", "Шифр"), `<span class="mono">${esc(c.cipher)}</span>`) : ""}${kvr("SHA-256", `<span class="mono">${esc(shortFp(l.sha256))}</span>`)}${kvr("SPKI", `<span class="mono">${esc(shortFp(l.spki_sha256))}</span>`)}${pki.length ? kvr(F.t("infra.internal_pki", "Внутренняя PKI"), pki.map(x => `<div class="mono">${esc(x.ad_domain ? `AD: ${x.ad_domain}` : x.host || x.url)}</div>`).join("")) : ""}${leg ? kvr(F.t("infra.legacy", "Устаревшее"), esc([...(leg.versions || []).filter(v => v.supported).map(v => v.version), ...(leg.weak_suites || []).map(w => w.name)].join(", ") || F.t("infra.not_accepted", "не принимаются"))) : ""}</div>`;
        })
        .join("")
    );
  }

  /** Short TLS summary for a host without an infra record (core: epoch not_after, days_left; demo: ISO). */
  function tlsSummary(t, today) {
    if (!t) return null;
    const iso = dateOf(t.not_after);
    const left =
      t.days_left != null
        ? t.days_left
        : Math.round((new Date(iso + "T00:00:00") - new Date(today + "T00:00:00")) / 864e5);
    return { cn: t.cn || null, iss: t.issuer || "-", iso, left, san: (t.san || []).join(", ") };
  }

  // ---------- segments ----------
  const navHost = h =>
    `dt-nav:${F.dataEntityPath ? F.dataEntityPath("host", h) : "/p/entity/host/" + enc(h)}`;
  const note = text => `<p class="fhint if-note">${ic("info")}<span>${text}</span></p>`;
  const more = id =>
    ` <button class="sec-a if-more" data-act="go:/help/${id}">${esc(F.t("common.details", "Подробнее"))}</button>`;
  const oosNote = () =>
    `<div class="banner info if-oos-b">${ic("info")}<div><b>${esc(F.t("infra.oos_banner_t", "Не проверялись, вне скоупа."))}</b> ${esc(F.t("infra.oos_banner_d", "Имена и адреса ниже найдены в сертификатах, DNS и у Microsoft. К ним не было ни одного запроса. В скоуп: только после подтверждения у заказчика."))}${more("oos-help")}</div></div>`;

  function segCerts() {
    const d = data();
    const certs = d.cert
      .slice()
      .sort(
        (a, b) =>
          (SEV_RANK[worst(a.issues || [])] ?? 9) - (SEV_RANK[worst(b.issues || [])] ?? 9) ||
          (a.days_left ?? 9e9) - (b.days_left ?? 9e9),
      );
    const bad = certs.filter(c => (c.issues || []).length).length;
    const rows = certs
      .map(c => {
        const l = leafOf(c) || { issuer: {} };
        const w = worst(c.issues || []);
        return ui.row({
          lead: ui.leadIcon("lock", w === "ok" ? "var(--ok)" : F.dataUtil ? F.dataUtil.SEVC[w] : ""),
          title: `<span class="mono">${esc(c.host)}:${esc(String(c.port))}</span>${c.mode && c.mode !== "tls" ? ` · ${esc(MODE[c.mode] || c.mode)}` : ""}`,
          sub: `${esc(l.issuer.cn || "-")} · ${esc(F.t("infra.until", { date: dmy(dateOf(l.not_after)) }, "до {date}"))}${c.days_left != null && c.days_left <= 30 ? ` (${daysText(c.days_left)})` : ""}<div class="dt-tags">${trustPill(c)}${issuePills(c)}</div>`,
          act: navHost(c.host),
        });
      })
      .join("");
    const ct = d.ct[0];
    const ab = ct ? ct.abandoned || [] : [];
    const tl = ct ? ct.timeline || [] : [];
    return (
      `<div class="dt-bar"><span class="dt-bar-n">${plural(certs.length, F.t("infra.cert_one", "сертификат"), F.t("infra.cert_few", "сертификата"), F.t("infra.cert_many", "сертификатов"))}${bad ? ` · ${F.t("infra.with_issues", { n: bad }, "с замечаниями {n}")}` : ""}</span></div>` +
      (certs.length
        ? `<div class="list">${rows}</div>`
        : note(
            F.t(
              "infra.certs_note",
              "Сертификаты проверяются в профилях «Стандартный» и «Полный». На открытых TLS-портах живых хостов скоупа.",
            ),
          )) +
      note(
        `${esc(F.t("infra.tls_note", "Срок, цепочка, имя и УЦ: по рукопожатию с портом; устаревшие версии TLS и STARTTLS: только в «Полном»."))}${more("tls-help")}`,
      ) +
      (ab.length
        ? ui.secH(F.t("infra.abandoned_title", "Заброшенные имена (CT)"), ab.length) +
          `<div class="list">${ab
            .map(a =>
              ui.row({
                lead: ui.leadIcon("history", "var(--warn)"),
                title: `<span class="mono">${esc(a.host)}</span>`,
                sub: `${esc(F.t("infra.last_expired", { date: dmy(dateOf(a.last_expiry)), n: plural(a.days_since_expiry, F.t("infra.day_one", "день"), F.t("infra.day_few", "дня"), F.t("infra.day_many", "дней")) }, "Последний сертификат истёк {date} · {n} назад"))}${a.last_issuer ? ` · ${esc(a.last_issuer)}` : ""}`,
                act: navHost(a.host),
              }),
            )
            .join("")}</div>` +
          note(
            F.t(
              "infra.abandoned_note",
              "Сертификаты для имени перестали продлевать, а зона жива. Забытый хост или кандидат на захват поддомена.",
            ),
          )
        : "") +
      (tl.length
        ? ui.secH(F.t("infra.ct_history", "История сертификатов (CT)"), tl.length) +
          `<div class="list">${tl
            .slice()
            .sort((a, b) => a.first_seen - b.first_seen)
            .map(t =>
              ui.row({
                lead: ui.leadIcon("lock"),
                title: `<span class="mono">${esc(t.host)}</span>`,
                sub: `${esc(F.t("infra.since", { date: dmy(dateOf(t.first_seen)) }, "с {date}"))} · ${plural(t.cert_count, F.t("infra.cert_one", "сертификат"), F.t("infra.cert_few", "сертификата"), F.t("infra.cert_many", "сертификатов"))}${t.ca_changes ? ` · ${F.t("infra.ca_changes", { n: t.ca_changes }, "смен УЦ: {n}")}` : ""} · ${esc((t.issuers || []).map(x => x.issuer).join(", "))}`,
                act: navHost(t.host),
              }),
            )
            .join("")}</div>`
        : "")
    );
  }

  function segMail() {
    const d = data();
    return (
      d.mail_policy
        .map(m => {
          const [ds, dcls] = DNSSEC[m.dnssec] || DNSSEC.unknown;
          const sts =
            m.mta_sts_policy && m.mta_sts_policy.mode
              ? m.mta_sts_policy.mode
              : m.mta_sts
                ? F.t("infra.record_present", "запись есть")
                : null;
          const caa = (m.caa || []).filter(r => r.tag === "issue" || r.tag === "issuewild");
          const issues = (m.issues || [])
            .slice()
            .sort((a, b) => (SEV_RANK[a.sev] ?? 9) - (SEV_RANK[b.sev] ?? 9));
          return (
            ui.secH(esc(m.domain)) +
            `<div class="kv if-mail">${kvr("MTA-STS", sts ? esc(sts) : pill("mute", F.t("infra.no", "нет")))}${kvr("TLS-RPT", m.tls_rpt ? `<span class="mono">${esc(typeof m.tls_rpt === "string" ? m.tls_rpt : F.t("infra.yes_present", "есть"))}</span>` : pill("mute", F.t("infra.no", "нет")))}${kvr("BIMI", m.bimi ? pill("ok", F.t("infra.yes_present", "есть"), "check") : pill("mute", F.t("infra.no", "нет")))}${kvr("CAA", caa.length ? `<span class="mono">${esc(caa.map(r => r.value).join(", "))}</span>` : pill("warn", F.t("infra.caa_none", "нет: любой УЦ"), "alert"))}${kvr("DNSSEC", pill(dcls, ds))}</div>` +
            (issues.length
              ? `<div class="list if-issues">${issues
                  .map(i =>
                    ui.row({
                      lead: ui.leadIcon(
                        i.sev === "info" ? "info" : "alert",
                        F.dataUtil ? F.dataUtil.SEVC[i.sev] : "",
                      ),
                      // Mail policy issues are core texts of the mail-* finding rules.
                      title: esc(F.ftext ? F.ftext.field(i.title, "mail-policy") : i.title),
                      sub: `${ui.sev(i.sev)}${i.detail ? ` <span class="muted">${esc(F.ftext ? F.ftext.field(i.detail, "mail-policy") : i.detail)}</span>` : ""}`,
                    }),
                  )
                  .join("")}</div>`
              : "")
          );
        })
        .join("") +
      note(
        F.t(
          "infra.mail_note",
          "SPF и DMARC: в карточке домена (раздел «Хосты», DNS-записи) и в находках «Почта».",
        ),
      )
    );
  }

  function segSaas() {
    const d = data();
    const hits = [];
    d.saas.forEach(s => (s.hits || []).forEach(h => hits.push({ ...h, domain: s.domain })));
    const byCat = {};
    hits.forEach(h => {
      const k = h.category || "other";
      const g = (byCat[k] = byCat[k] || {});
      (g[h.id] = g[h.id] || { ...h, ev: [] }).ev.push(h);
    });
    const saasHtml = Object.keys(byCat).length
      ? Object.entries(byCat)
          .map(
            ([cat, svc]) =>
              `<div class="if-cat"><div class="if-cat-h">${esc(SAAS_CAT[cat] || cat)}</div><div class="list">${Object.values(
                svc,
              )
                .map(s =>
                  ui.row({
                    lead: ui.leadIcon("db", "var(--accent)"),
                    title: esc(s.name),
                    sub: s.ev
                      .map(
                        e =>
                          `<span class="pill mute">${esc(EVIDENCE[e.evidence] || e.evidence)}</span> <span class="mono if-rec">${esc(e.record)}</span>`,
                      )
                      .join("<br>"),
                  }),
                )
                .join("")}</div></div>`,
          )
          .join("")
      : note(F.t("infra.saas_none", "Сервисы организации по DNS-записям не определены."));
    const unknown = [].concat(...d.saas.map(s => s.unknown || []));
    const tenant = d.tenant.find(t => t.exists);
    const tenantHtml = tenant
      ? ui.secH("Microsoft 365") +
        `<div class="kv if-tenant">${kvr(F.t("infra.tenant", "Арендатор"), `<span class="mono">${esc((tenant.openid || {}).tenant_id || "-")}</span>`)}${kvr(F.t("infra.region", "Регион"), esc((tenant.openid || {}).region_scope || "-"))}${kvr(F.t("infra.signin", "Вход"), (tenant.realm || {}).namespace === "federated" ? pill("warn", F.t("infra.federated", "Федерация (свой сервер входа)"), "users") : (tenant.realm || {}).namespace === "managed" ? pill("ok", F.t("infra.managed", "Облачный (Entra ID)"), "check") : pill("mute", F.t("infra.undetermined", "не определён")))}${tenant.federation_host ? kvr("AD FS", `<span class="mono">${esc(tenant.federation_host)}</span>`) : ""}${(tenant.tenant_domains || []).length ? kvr(F.t("infra.domains", "Домены"), `<span class="mono">${esc(tenant.tenant_domains.join(", "))}</span>`) : ""}</div>` +
        note(
          `${esc(F.t("infra.m365_note", "Сведения из открытых эндпоинтов Microsoft (OpenID, getuserrealm). К серверам заказчика запросов не было."))}${more("m365-help")}`,
        )
      : "";
    const cdnHosts = (F.db.hosts || []).filter(h => h.cdn);
    const cdnHtml = cdnHosts.length
      ? ui.secH(F.t("infra.cdn_clouds", "CDN и облака"), cdnHosts.length) +
        `<div class="list">${cdnHosts
          .map(h =>
            ui.row({
              lead: ui.leadIcon("globe", h.cdn.kind === "cdn" ? "var(--accent)" : ""),
              title: `<span class="mono">${esc(h.name)}</span>`,
              sub: `${esc(h.cdn.name || h.cdn.provider)} · ${h.cdn.kind === "cdn" ? "CDN" : h.cdn.kind === "cloud" ? F.t("infra.cloud_lc", "облако") : F.t("infra.hosting_lc", "хостинг")} · <span class="mono">${esc(h.cdn.prefix || h.cdn.ip || "")}</span>`,
              act: navHost(h.name),
            }),
          )
          .join("")}</div>`
      : "";
    const cands = [];
    d.origin.forEach(o => (o.candidates || []).forEach(c => cands.push({ ...c, cdn: o.cdn })));
    const originHtml = cands.length
      ? ui.secH(F.t("infra.origin_title", "Кандидаты origin за CDN"), cands.length) +
        `<div class="list">${cands
          .sort((a, b) => b.score - a.score)
          .map(c =>
            ui.row({
              lead: ui.leadIcon("target", "var(--warn)"),
              title: `<span class="mono">${esc(c.ip)}</span>`,
              sub: `${esc((c.reasons || []).map(r => ORIGIN_REASON[r] || r).join(", "))}${(c.sources || []).length ? ` · ${esc(c.sources.map(s => s.detail || s.kind).join(", "))}` : ""}<div class="dt-tags">${pill("mute", F.t("infra.score", { n: c.score }, "оценка {n}"))}${pill("info", F.t("infra.to_verify", "для проверки"))}</div>`,
            }),
          )
          .join("")}</div>` +
        note(
          F.t(
            "infra.origin_note",
            "Возможные исходные адреса сайта за CDN, собранные из DNS (MX, SPF, поддомены). Запросов к ним не было; проверка без SNI: только в «Полном» и только для адресов из скоупа.",
          ),
        )
      : "";
    const oos = d.oos;
    const oosHtml = oos.length
      ? ui.secH(F.t("infra.oos_title", "Кандидаты вне скоупа"), oos.length) +
        oosNote() +
        `<div class="list">${oos
          .map(o =>
            ui.row({
              lead: ui.leadIcon("info", "var(--text-3)"),
              title: `<span class="mono">${esc(o.host)}</span>`,
              sub: `${o.via ? esc(o.via) : ""}<div class="dt-tags">${pill("mute if-oos-src", esc(OOS_SRC[o.kind] || o.kind))}${pill("warn", F.t("infra.not_checked_lc", "не проверялся"), "shield")}</div>`,
              act: "go:/p/out-of-scope",
            }),
          )
          .join("")}</div>`
      : "";
    return (
      `<div class="dt-bar"><span class="dt-bar-n">${plural(
        Object.values(byCat).reduce((a, g) => a + Object.keys(g).length, 0),
        F.t("infra.svc_one", "сервис"),
        F.t("infra.svc_few", "сервиса"),
        F.t("infra.svc_many", "сервисов"),
      )}${tenant ? " · Microsoft 365" : ""}${cdnHosts.length ? ` · ${F.t("infra.cdn_count", { n: cdnHosts.length }, "CDN/облака: {n}")}` : ""}</span></div>` +
      ui.secH(F.t("infra.saas_title", "Сервисы организации")) +
      saasHtml +
      (unknown.length
        ? note(
            `${esc(F.t("infra.unknown_verif", "Нераспознанные записи проверки:"))} <span class="mono">${esc(unknown.join(", "))}</span>`,
          )
        : "") +
      tenantHtml +
      cdnHtml +
      originHtml +
      oosHtml
    );
  }

  /** Enumeration summary (dns_enum) for the hosts segment. */
  function enumSummary() {
    const e = data().dns_enum;
    if (!e.length) return "";
    const parts = e.map(r => {
      const b = r.brute || {};
      if (b.skipped)
        return `${esc(r.domain)}: ${esc(F.t("infra.bf_skipped", "перебор не запускался"))} (${b.skipped === "headless" ? F.t("infra.bg_monitor", "фоновый мониторинг") : b.skipped === "off" ? F.t("infra.off_wizard", "выключен в мастере") : b.skipped === "url_target" ? F.t("infra.bf_url_target", "цель: URL, поддомены вне скоупа") : esc(String(b.skipped))})`;
      if (b.error) return `${esc(r.domain)}: ${esc(F.t("infra.bf_aborted", "перебор прерван"))}`;
      const wl = (b.wildcard_levels || []).length;
      return `${esc(r.domain)}: ${esc(F.t("infra.bf_done", { wl: r.wordlist || "", tried: b.tried || 0, hits: b.hits || 0 }, "перебор {wl}: проверено {tried}, найдено {hits}"))}${r.permute ? `, ${F.t("infra.bf_permute", { n: r.permute.hits || 0 }, "перестановки: {n}")}` : ""}${wl ? ` · wildcard: ${wl}` : ""}${b.throttled ? F.t("infra.throttled", " · сеть ограничивала DNS: темп снижен") : ""}`;
    });
    return `<p class="fhint if-enum">${ic("search")}${parts.join("<br>")}</p>`;
  }

  const counts = {
    certs: () => data().cert.length + ((data().ct[0] || {}).abandoned || []).length,
    mailpol: () => data().mail_policy.length,
    saas: () =>
      data().saas.reduce((a, s) => a + (s.hits || []).length, 0) +
      data().tenant.length +
      (F.db.hosts || []).filter(h => h.cdn).length +
      data().origin.length +
      data().oos.length,
  };

  F.infra = {
    ROLE,
    HOST_SRC,
    SAAS_CAT,
    OOS_SRC,
    CODE,
    data,
    srcLabel,
    isEnumSrc,
    roleChips,
    priorityPill,
    cdnPill,
    srcPill,
    certsOf,
    certBlock,
    tlsSummary,
    enumSummary,
    seg: { certs: segCerts, mailpol: segMail, saas: segSaas },
    counts,
  };
})();
