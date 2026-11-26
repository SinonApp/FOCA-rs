// Demo: captcha in dorks. One "pass verification (N)" button walks through every engine stuck on a captcha,
// Settings → Network → prepare search engines, Debug → Search (search browser fingerprint, a page for
// Chrome, per-engine log), the new Yahoo / public SearXNG sources, and the help article.
// qa/shoot.sh --routes /p/overview --out $PWD/qa/scenarios/captcha --steps $PWD/qa/scenarios/captcha/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const snack = () => ev(() => document.querySelector("#snack")?.textContent || "");
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/captcha_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const noOvf = async n => ok(`${n}: no horizontal overflow`, (await overflow()) <= 1, await overflow());
  const click = sel => ev(s => { const e = document.querySelector(s); if (e) e.click(); return !!e; }, sel);
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    // Scan: Startpage (demo) and Mojeek on a captcha share one button.
    await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "passive" })); await wait(300);
    await ev(() => FOCA.api.scan_pause()); await go("/p/scan"); await wait(300);
    await ev(() => {
      const S = FOCA.scan.sources; let m = S.find(s => s.id === "mojeek"); if (!m) { m = { id: "mojeek", name: "Mojeek (дорки)" }; S.push(m); }
      Object.assign(m, { status: "blocked", n: 0, error: "капча / заблокировано: поисковик показал капчу", verifyUrl: "https://www.mojeek.com/search?q=foca", retryAsked: false });
      FOCA.render(true);
    }); await wait(300);
    let t = await ev(() => document.querySelector("#scn-vall")?.textContent || "");
    ok("banner: both search engines in captcha, dorks handed to others", /Нужна проверка/.test(t) && /Startpage/.test(t) && /Mojeek/.test(t) && /не потеряны/.test(t), t.slice(0, 240));
    ok('single "Пройти проверку (2)" button', /Пройти проверку \(2\)/.test(t), t.slice(0, 240));
    await ev(() => document.querySelector("#scn-vall")?.scrollIntoView({ block: "center" }));
    await shot("verify_all"); await noOvf("scan: verification banner");
    await ev(() => { window.__vs = []; const o = FOCA.api.platform_verify_search; FOCA.api.platform_verify_search = a => { window.__vs.push(a.url); return o(a); }; });
    await click('[data-act="scan-verify-all"]'); await wait(1500);
    const vs = await ev(() => window.__vs);
    ok("sequential verification: Startpage, then Mojeek", vs.length === 2 && /startpage/.test(vs[0]) && /mojeek/.test(vs[1]), vs);
    t = await ev(() => document.querySelector("#scn-vall")?.textContent || "");
    ok("banner gone after sequential verification", !/Нужна проверка/.test(t), t.slice(0, 200));
    const asked = await ev(() => FOCA.scan.sources.filter(s => s.id === "startpage").map(s => s.retryAsked || s.status));
    ok("Startpage queued for retry", asked.length === 1 && asked.every(x => x === true || x === "ok" || x === "running"), asked);
    await ev(() => FOCA.api.scan_stop({ reason: "user" })); await wait(300);
    // Settings → Network: prepare search engines.
    await go("/settings/network");
    t = await txt();
    ok('Network: "Поисковики (дорки)" section and button', /Поисковики \(дорки\)/.test(t) && /Подготовить поисковики/.test(t) && /Автоматического решения капчи нет/.test(t), t.slice(-400));
    await ev(() => document.querySelector('[data-act="st-prep-engines"]')?.scrollIntoView({ block: "center" }));
    await shot("prep"); await noOvf("Network: preparation");
    await ev(() => { window.__vs = []; });
    await click('[data-act="st-prep-engines"]'); await wait(800);
    const pv = await ev(() => window.__vs);
    ok("preparation: Startpage, Brave, Yahoo, Mojeek opened", pv.length === 4 && /yahoo/.test(pv[2]), pv);
    ok("preparation: all 4 search engines in turn", /подготовлено: 4/.test(await snack()), await snack());
    // Debug → Search.
    await go("/settings/debug/search"); await wait(400);
    t = await txt();
    ok("Debug → Search: per-engine log", /Startpage/.test(t) && /отдано другим 2/.test(t) && /взято у других 2/.test(t) && /SearXNG/.test(t), t.slice(0, 300));
    await click('[data-act="dbg-fp"]'); await wait(600);
    t = await txt();
    ok("fingerprint: visibilityState visible, Client Hints, no automation signs", /visibilityState/.test(t) && /visible/.test(t) && /Client Hints/.test(t) && /Признаков «сломанного» браузера нет/.test(t), t.slice(0, 300));
    await shot("fingerprint"); await noOvf("Debug: fingerprint");
    await click('[data-act="dbg-fp-page"]'); await wait(500);
    ok("Chrome page: saved/shared", /Chrome/.test(await snack()), await snack());
    const segs = await ev(() => [...document.querySelectorAll(".dbg-seg button")].map(b => b.textContent));
    ok('"Поиск" tab among Debug tabs', segs.includes("Поиск"), segs);
    // Sources: Yahoo and SearXNG.
    await go("/settings/sources"); await wait(300);
    await ev(() => { FOCA.state.srcOpen.search = true; FOCA.render(true); }); await wait(300);
    t = await ev(() => (FOCA.page() || document.body).textContent);
    ok("Sources: Yahoo and public SearXNG", /Yahoo \(через браузер\)/.test(t) && /Публичные SearXNG/.test(t), t.slice(0, 200));
    // Help.
    await go("/help/captcha"); await wait(300);
    t = await txt();
    ok('Help "капча": failover, single button, IP reputation', /не теряются/.test(t) && /Пройти проверку/.test(t) && /репутация IP/.test(t) && /Подготовить поисковики/.test(t), t.slice(0, 300));
    await shot("help"); await noOvf("help");
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/captcha_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
