// Demo: port scan "unreliable" (device VPN/proxy), Startpage captcha with "verification needed" + "pass
// verification" → source retry, the "rate limited" status (429), a partial success note, the help article.
// qa/shoot.sh --routes /p/overview --out $PWD/qa/scenarios/source-statuses --steps $PWD/qa/scenarios/source-statuses/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/source_statuses_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const noOvf = async n => ok(`${n}: no horizontal overflow`, (await overflow()) <= 1, await overflow());
  const rowT = id => ev(id => document.querySelector(`#scn-src-${id}`)?.textContent || "", id);
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    // Scan: Startpage on a captcha (demo).
    await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "passive" })); await wait(300);
    await ev(() => FOCA.api.scan_pause()); await go("/p/scan"); await wait(300);
    let t = await rowT("startpage");
    ok('Startpage: "Нужна проверка" and "Пройти проверку" button', /Нужна проверка/.test(t) && /Пройти проверку/.test(t), t.slice(0, 200));
    await ev(() => document.querySelector("#scn-src-startpage")?.scrollIntoView({ block: "center" }));
    await shot("captcha"); await noOvf("scan: captcha");
    await ev(() => document.querySelector('[data-act="scan-verify-src:startpage"]')?.click()); await wait(1200);
    t = await rowT("startpage");
    ok("after verification: source queried again → OK", /OK/.test(t) && !/Пройти проверку/.test(t), t.slice(0, 200));
    // Core statuses: unreliable (ports), limit (OTX), ok with a note (CC).
    await ev(() => {
      const S = FOCA.scan.sources, put = (id, name, o) => { let x = S.find(s => s.id === id); if (!x) { x = { id, name }; S.push(x); } Object.assign(x, o); };
      put("ports", "Скан портов", { status: "unreliable", n: 0, error: "Скан портов недостоверен: сеть устройства (VPN, AdGuard, прокси) принимает соединения на любом порту. Отключите локальный VPN или добавьте FOCA-rs в исключения" });
      put("otx_dns", "OTX passive DNS", { status: "limit", n: 0, error: "сервис ограничил частоту запросов (HTTP 429): повторы с паузой не помогли; повторите скан позже или с другой сети" });
      put("cc", "Common Crawl", { status: "ok", n: 4, error: "часть индексов недоступна (CC-MAIN-2026-43-index: HTTP 504), данные из ответивших" });
      FOCA.render(true);
    }); await wait(300);
    t = await rowT("ports");
    ok('ports: "Недостоверно" + "Что делать"', /Недостоверно/.test(t) && /VPN/.test(t) && /Что делать/.test(t), t.slice(0, 200));
    t = await rowT("otx_dns");
    ok('OTX: "Лимит запросов", not "Ошибка"', /Лимит запросов/.test(t) && !/Ошибка/.test(t) && /429/.test(t), t.slice(0, 200));
    t = await rowT("cc");
    ok("CC: OK with a note about an unavailable index", /OK/.test(t) && /часть индексов недоступна/.test(t), t.slice(0, 200));
    await ev(() => document.querySelector("#scn-src-ports")?.scrollIntoView({ block: "center" }));
    await shot("statuses"); await noOvf("scan: statuses");
    await ev(() => document.querySelector("#scn-src-ports [data-act^='go:/help/']")?.click()); await wait(500);
    t = await txt();
    ok('"Что делать" button → "Скан портов недостоверен" article', /канарейк/.test(t) && /AdGuard/.test(t), t.slice(0, 300));
    await shot("help"); await noOvf("help");
    await ev(() => FOCA.api.scan_stop({ reason: "user" })); await wait(300);
    // Retrying after the search stage has ended gives the real reason.
    const r = await ev(() => FOCA.api.scan_retry_source("startpage"));
    ok("scan_retry_source outside search stage: ok=false with reason", r && r.ok === false && /следующий скан/.test(r.reason || ""), r);
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/source_statuses_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
