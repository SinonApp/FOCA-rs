// Texts produced by the core in English and Ukrainian: source details (captcha, blocked IP, dorks handed
// over, rate limit, timeout), the "retry source" reason and the wordlist catalogue. The core sends the
// Russian text plus `<field>_msg` = { code, params }; the UI renders locales/<lang>/ui/core.json.
// EN details must contain no Cyrillic, UK details no Russian-only letters (ы э ъ ё).
// Run: qa/shoot.sh --routes none --out $PWD/qa/out/i18n-core --steps $PWD/qa/scenarios/i18n-core/steps.mjs
import fs from "fs";

// Source events exactly as the engine emits them (text + message code, see i18n::classify).
const CAPTCHA = { code: "src.captcha", params: {}, text: "поисковик показал капчу" };
const EVENTS = [
  {
    id: "mojeek",
    name: "Mojeek (дорки)",
    status: "blocked",
    n: 0,
    error: "капча / заблокировано: поисковик заблокировал IP (automated queries)",
    error_msg: {
      code: "src.blocked",
      params: {
        why: { code: "src.ip_blocked", params: {}, text: "поисковик заблокировал IP (automated queries)" },
      },
    },
  },
  {
    id: "ddg",
    name: "DuckDuckGo (дорки)",
    status: "ok",
    n: 3,
    error:
      "взял у других поисковиков групп: 1; остановлен: поисковик показал капчу (HTTP 202); оставшиеся дорки переданы другим поисковикам",
    error_msg: {
      code: "join",
      parts: [
        { code: "src.took_over", params: { n: "1" }, text: "взял у других поисковиков групп: 1" },
        {
          code: "src.captcha_handoff",
          params: {
            why: { code: "src.captcha_http", params: { status: "202" }, text: "поисковик показал капчу (HTTP 202)" },
          },
          text: "остановлен: поисковик показал капчу (HTTP 202); оставшиеся дорки переданы другим поисковикам",
        },
      ],
    },
  },
  {
    id: "otx_dns",
    name: "OTX passive DNS",
    status: "limit",
    n: 0,
    error:
      "сервис ограничил частоту запросов (HTTP 429): повторы с паузой не помогли; повторите скан позже или с другой сети",
    error_msg: { code: "src.limit", params: {} },
  },
  {
    id: "crt",
    name: "crt.sh",
    status: "timeout",
    n: 0,
    error: "нет ответа за 90 с",
    error_msg: { code: "src.no_reply_s", params: { s: "90" } },
  },
];
// startpage comes from the demo backend itself (captcha with error_msg).
const IDS = ["startpage", ...EVENTS.map(e => e.id)];
const CYR = /[\u0400-\u04FF]/;
const RU_ONLY = /[ыэъёЫЭЪЁ]/;

export default async (page, { out, go }) => {
  const log = [];
  let fails = 0;
  const ok = (name, cond, data) => {
    if (!cond) fails++;
    log.push([cond ? "OK" : "FAIL", name, data]);
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const bad = (lang, s) => (lang === "en" ? CYR.test(s) : RU_ONLY.test(s));
  try {
    await go("/projects");
    await ev(() => {
      FOCA.api.demo_reset();
      FOCA.api.terms_accept("1");
      return FOCA.api.project_open("contoso");
    });
    await wait(250);
    await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "passive" }));
    await wait(300);
    await ev(() => FOCA.api.scan_pause());
    for (const lang of ["en", "uk"]) {
      await ev(l => FOCA.i18n.setLang(l), lang);
      await wait(300);
      await ev(evs => evs.forEach(e => FOCA.emit("scan", { type: "source", scan_id: FOCA.scan.id, ...e })), EVENTS);
      await ev(() => FOCA.go("/p/scan"));
      await wait(450);
      for (const id of IDS) {
        const sub = await ev(id => document.querySelector(`#scn-src-${id} .s`)?.innerText || "", id);
        ok(`${lang}: ${id} detail rendered in the UI language`, sub && !bad(lang, sub), sub);
      }
      const ddg = await ev(() => document.querySelector("#scn-src-ddg .s")?.innerText || "");
      ok(
        `${lang}: joined note keeps both parts`,
        (lang === "en" ? /other engines/ : /іншим пошуковикам/).test(ddg) && /202/.test(ddg),
        ddg,
      );
      await page.screenshot({ path: `${out}/i18n_core_scan_${lang}.png` });
      const reason = await ev(() =>
        Promise.resolve(FOCA.api.scan_retry_source("startpage")).then(r =>
          r && r.ok === false ? FOCA.coreMsg(r.reason, r.reason_msg) : "ok",
        ),
      );
      ok(`${lang}: retry-source reason`, reason === "ok" || (reason && !bad(lang, reason)), reason);
      await ev(() => FOCA.go("/settings/wordlists"));
      await wait(500);
      const names = await ev(() => [...document.querySelectorAll("[data-wl] .t")].map(e => e.innerText));
      ok(`${lang}: wordlist catalogue listed`, names.length >= 5, names.length);
      const wrong = names.filter(n => bad(lang, n));
      ok(`${lang}: wordlist names translated`, wrong.length === 0, wrong);
      await page.screenshot({ path: `${out}/i18n_core_wordlists_${lang}.png` });
    }
    // RU keeps the core's exact wording.
    await ev(() => FOCA.i18n.setLang("ru"));
    await wait(300);
    const ru = await ev(() => FOCA.coreMsg("x", { code: "src.no_reply_s", params: { s: "90" } }));
    ok("ru: message equals the core text", ru === "нет ответа за 90 с", ru);
    await ev(() => FOCA.api.scan_stop({ reason: "user" }));
  } catch (e) {
    fails++;
    log.push(["FAIL", "exception", String((e && e.stack) || e)]);
  }
  fs.writeFileSync(`${out}/i18n_core_steps.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(
    log
      .map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`)
      .join("\n"),
  );
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
