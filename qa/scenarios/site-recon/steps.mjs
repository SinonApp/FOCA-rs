// Demo: site recon. Data segments (site technologies, site, JS and API, cloud, code), empty states with
// a reason, sources in the recon group, the scan stage, the help article.
// qa/shoot.sh --routes /p/overview --out $PWD/qa/scenarios/site-recon --w 393 --theme dark --steps $PWD/qa/scenarios/site-recon/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/site_recon_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const noOvf = async n => ok(`${n}: no horizontal overflow`, (await overflow()) <= 1, await overflow());
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    // Site technologies.
    await go("/p/data/tech");
    let t = await txt();
    ok("data: recon segment chips", ["Технологии сайта", "Сайт", "JS и API", "Облако", "Код в репозиториях"].every(x => t.includes(x)));
    ok('technologies: versions and "Устарело"', /Nginx/.test(t) && /1\.18\.0/.test(t) && /Устарело/.test(t), t.slice(0, 300));
    await shot("tech"); await noOvf("technologies");
    // Site: favicon with copyable queries.
    await go("/p/data/site");
    t = await txt();
    ok("site: favicon mmh3 and Shodan/FOFA/Censys queries", /mmh3 -?\d+/.test(t) && /Shodan/.test(t) && /FOFA/.test(t) && /Censys/.test(t), t.slice(0, 300));
    ok("site: analytics IDs and hidden paths", /ID аналитики/.test(t) && /G-/.test(t) && /Скрытые пути/.test(t));
    const copied = await ev(() => { let got = null; const o = FOCA.actions.copy; FOCA.actions.copy = x => { got = x; }; document.querySelector('[data-act="dt-rc-copy:1"]').click(); FOCA.actions.copy = o; return got; });
    ok("site: button copies a ready Shodan query", /^http\.favicon\.hash:-?\d+$/.test(copied || ""), copied);
    await shot("site"); await noOvf("site");
    // JS and API: secrets masked only.
    await go("/p/data/js");
    t = await txt();
    ok("JS: endpoints", /Эндпоинты/.test(t) && /\/api\/v1\/tariffs/.test(t));
    ok('JS: secret, mask "…", no value', !/Секреты в JavaScript/.test(t) || /AIza…/.test(t));
    await noOvf("JS");
    // Cloud, code.
    await go("/p/data/cloud");
    t = await txt();
    ok("cloud: bucket with status", /Amazon S3/.test(t) && /(Закрыт|Не проверялся|Открытый листинг)/.test(t) || /Облачных хранилищ не найдено/.test(t), t.slice(0, 200));
    await go("/p/data/code");
    t = await txt();
    ok("code: grep.app hits or reason", /grep\.app/.test(t), t.slice(0, 200));
    // Scan comparison: site technologies.
    await go("/p/diff");
    t = await txt();
    ok('scan diff: "Технологии сайта" group (new and version-changed)', /Технологии сайта/.test(t) && /1\.12\.4 →/.test(t), t.slice(0, 300));
    await shot("diff"); await noOvf("diff");
    // Empty state with a reason: a project where grep.app is blocked.
    await ev(() => FOCA.api.project_open("logistics")); await wait(300);
    await go("/p/data/code");
    t = await txt();
    ok('code: empty, reason "защита от ботов"', /защиту от ботов/.test(t), t.slice(0, 300));
    await shot("code_blocked");
    // Sources: the recon group.
    await go("/settings/sources");
    await ev(() => { document.querySelectorAll("details").forEach(d => { d.open = true; }); });
    t = await txt();
    ok('sources: recon/wellknown/buckets/grepapp in "Разведка"', /Разведка/.test(t) && /grep\.app/.test(t) && /security\.txt/.test(t) && /Облачные хранилища/.test(t));
    // Scan: the site recon stage.
    ok("demo: recon stage in pipeline", await ev(() => FOCA_DEMO_BACKEND.STAGES.some(s => s.id === "recon")));
    // Help.
    await go("/help/recon-help");
    t = await txt();
    ok('help: "Разведка сайта" article', /Разведка сайта/.test(t) && /Shodan/.test(t));
    await noOvf("help");
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/site_recon_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
