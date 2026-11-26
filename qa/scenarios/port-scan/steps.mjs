// Demo: port scan. The ports block on the host card (scan / InternetDB cache, sensitive services),
// the module in the "full" wizard (top 100/1000), the scan stage and source, settings, the help article.
// qa/shoot.sh --routes /p/overview --out $PWD/qa/scenarios/port-scan --w 393 --theme dark --steps $PWD/qa/scenarios/port-scan/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/port_scan_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const noOvf = async n => ok(`${n}: no horizontal overflow`, (await overflow()) <= 1, await overflow());
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    // Host card: ports from the scan, RDP flagged as sensitive.
    await go("/p/entity/host/portal.contoso.example");
    let t = await txt();
    ok('host: "Порты" block and scan summary', /Порты/.test(t) && /Скан портов топ-100/.test(t) && /открыто 2/.test(t), t.slice(0, 400));
    ok('host: 3389/tcp rdp, "скан" and "RDP из интернета"', /3389\/tcp/.test(t) && /RDP из интернета/.test(t) && /скан/.test(t), t.slice(0, 600));
    await ev(() => { const r = document.querySelector(".dt-ports-sum"); if (r) r.scrollIntoView({ block: "center" }); });
    await shot("host_ports"); await noOvf("host card");
    // InternetDB cache (mail: Shodan banners).
    await go("/p/entity/host/mail.contoso.example");
    t = await txt();
    ok("mail host: ports from InternetDB cache are marked", /кэш InternetDB/.test(t), t.slice(0, 400));
    // "Full" wizard: ports module, top 100/1000.
    await go("/new");
    await ev(() => { const b = document.querySelector('[data-act="la-prof:full"]') || [...document.querySelectorAll("[data-act]")].find(x => /la-prof/.test(x.dataset.act) && /full/.test(x.dataset.act)); if (b) b.click(); }); await wait(350);
    t = await txt();
    ok('wizard: "Скан портов" block with Top-100/Top-1000', /Скан портов/.test(t) && /Топ-100/.test(t) && /Топ-1000/.test(t), t.slice(0, 300));
    await ev(() => document.querySelector('[data-act="la-ports-top:1000"]').click()); await wait(250);
    ok("wizard: top-1000 selected", await ev(() => document.querySelector('[data-act="la-ports-top:1000"]').classList.contains("on")));
    await shot("launch_ports"); await noOvf("wizard");
    // Scan: the ports stage and source (demo, "full").
    ok("demo: ports stage in pipeline", await ev(() => FOCA_DEMO_BACKEND.STAGES.some(s => s.id === "ports")));
    await ev(() => FOCA.actions["scan-start"]({ profile: "full", active: true, open: true, ports: { top: 100 } })); await wait(300);
    await ev(() => FOCA.api.scan_pause()); await wait(150);
    const src = await ev(() => (FOCA.scan.sources || []).find(s => s.id === "ports"));
    ok('"Полный" scan: ports source waiting', src && src.status === "wait", src);
    await ev(() => FOCA.api.scan_stop()); await wait(250);
    await ev(() => FOCA.actions["scan-start"]({ profile: "std", open: true })); await wait(300);
    const src2 = await ev(() => (FOCA.scan.sources || []).find(s => s.id === "ports"));
    ok('"Стандартный" scan: ports source off', src2 && src2.status === "off", src2);
    await ev(() => FOCA.api.scan_stop()); await wait(250);
    // Settings and help.
    await go("/settings/network");
    t = await txt();
    ok('network settings: "Скан портов" (top-100/1000/custom list)', /Скан портов/.test(t) && /Свой список/.test(t), t.slice(-400));
    await go("/settings/sources");
    await ev(() => { document.querySelectorAll("details").forEach(d => { d.open = true; }); });
    t = await txt();
    ok('sources: "Скан портов" in "Разведка" group', /Скан портов/.test(t));
    // Monitoring: rescan profile and a note about the app being killed.
    await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    await go("/p/monitor");
    await ev(() => { const b = document.querySelector('[data-act="v2mo-mode:weekly"]'); if (b) b.click(); }); await wait(250);
    t = await txt();
    ok("monitoring: Passive/Standard profile, active ones manual only", /Профиль повторного скана/.test(t) && /Стандартный/.test(t) && /только вручную/.test(t), t.slice(0, 300));
    ok('monitoring: "Пора пересканировать" reminder if the app was killed', /Пора пересканировать/.test(t));
    await ev(() => document.querySelector('[data-act="v2mo-prof:std"]').click()); await wait(250);
    ok("monitoring: profile saved in settings.monitor", await ev(() => ((FOCA.db.settings.monitor || {}).contoso || {}).profile === "std"));
    await shot("monitor"); await noOvf("monitoring");
    // Notification route: /open/<project> opens the project.
    await ev(() => FOCA.api.project_open("logistics")); await wait(250);
    await go("/open/contoso");
    await wait(400);
    ok('/open/contoso: contoso project opened, "Обзор" screen', await ev(() => FOCA.db.project.id === "contoso" && FOCA.cur && /overview/.test(FOCA.cur.path || location.hash)), await ev(() => [FOCA.db.project.id, location.hash]));
    await go("/help/ports-help");
    t = await txt();
    ok('help: "Скан портов" article', /Скан портов/.test(t) && /кэш InternetDB/.test(t) && /исключени/.test(t));
    await noOvf("help");
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/port_scan_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
