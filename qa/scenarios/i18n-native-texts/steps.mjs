// Demo: texts the UI hands to native code or takes verbatim from the core follow the UI language,
// the language reported to the Android bridge, the captcha verify screen title and the site file
// search estimate note in the launch wizard.
// qa/shoot.sh --routes none --out $PWD/qa/out/i18n-native-texts --steps $PWD/qa/scenarios/i18n-native-texts/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const RU = /[ыэъё]|через браузер|нет веб-адресов/i;
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    await ev(() => { window.__langs = []; window.FocaNative = { setLang: l => window.__langs.push(l), setBars() {}, ready() {} }; });
    for (const lang of ["uk", "en"]) {
      await ev(l => FOCA.i18n.setLang(l), lang); await wait(400);
      const langs = await ev(() => window.__langs);
      ok(`${lang}: language reported to the native bridge`, langs[langs.length - 1] === lang, langs);

      // Captcha verify title for a single engine.
      await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "passive" })); await wait(300);
      await ev(() => FOCA.api.scan_pause()); await ev(() => FOCA.go("/p/scan")); await wait(400);
      await ev(() => {
        const S = FOCA.scan.sources; let s = S.find(x => x.id === "startpage");
        if (!s) { s = { id: "startpage", name: "Startpage (через браузер)" }; S.push(s); }
        Object.assign(s, { name: "Startpage (через браузер)", status: "blocked", n: 0, verifyUrl: "https://www.startpage.com/sp/search?q=x", retryAsked: false, verifyDone: false });
        window.__titles = [];
        if (!window.__verifyOrig) {
          window.__verifyOrig = FOCA.api.platform_verify_search;
          FOCA.api.platform_verify_search = a => { window.__titles.push(a.title); return window.__verifyOrig(a); };
        }
        FOCA.actions["scan-verify-src"]("startpage");
      }); await wait(500);
      const titles = await ev(() => window.__titles);
      const want = await ev(() => FOCA.t("sources.name_startpage", "?"));
      ok(`${lang}: verify title is the localized source name`, titles.length === 1 && titles[0] === want && (lang !== "en" || !/[а-яё]/i.test(titles[0])), [titles, want]);
      await ev(() => FOCA.api.scan_stop({ reason: "user" })); await wait(300);

      // Site file search estimate: the core note "no web addresses in scope" with its message code.
      await ev(() => {
        FOCA.api.fuzz_estimate = () => Promise.resolve({ hosts: [], requests: 0, seconds: 0, note: "нет веб-адресов в скоупе", note_msg: { code: "fuzz.no_urls", params: {} } });
        FOCA.state.launch.leave = true; FOCA.go("/new");
      }); await wait(300);
      await ev(() => FOCA.actions["la-prof"]("full")); await wait(900);
      const est = await ev(() => document.querySelector("#la-fz-est")?.textContent || "");
      ok(`${lang}: estimate note is translated`, est.length > 3 && !RU.test(est), est);
      await page.screenshot({ path: `${out}/i18n_native_${lang}_${tag}.png` });
    }
    await ev(() => FOCA.i18n.setLang("auto")); await wait(300);
  } catch (e) { fails++; log.push(["FAIL", "exception", String((e && e.stack) || e)]); }
  fs.writeFileSync(`${out}/i18n_native_texts_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
