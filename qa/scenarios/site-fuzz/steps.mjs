// Demo: "full" with the forgotten file discovery block (modules, estimate, rate) and no claims of a
// port scan/HttpMap; fuzz counters and "stop fuzzing" on the scan screen; site search findings;
// Settings → Wordlists (download, import, delete); the "found on site" report section.
// qa/shoot.sh --routes /p/overview --out qa/scenarios/site-fuzz --steps $PWD/qa/scenarios/site-fuzz/steps.mjs
import fs from "fs";
export default async (page, { out, prep }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const go = async r => { await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(250); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).innerText);
  const act = async (a, arg) => { await ev(([a, arg]) => FOCA.actions[a](arg, document.querySelector(`[data-act="${a}${arg !== undefined ? ":" + arg : ""}"]`)), [a, arg]); await wait(250); };
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/site_fuzz_${n}.png` }); };
  const ff = n => ev(n => window.FOCA_DEMO_BACKEND._ff(n), n);
  try {
    await go("/projects"); await ev(() => FOCA.api.demo_reset()); await wait(200);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(200);
    // Wizard: "full".
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go("/new"); }); await wait(250);
    await act("la-prof", "full"); await wait(500);
    let t = await txt();
    ok('"Полный" without port scan/HttpMap/vulnerabilities', !/HttpMap|Порт-скан|порт-скан|уязвимост/.test(t), t.slice(0, 300));
    ok('"Полный": forgotten-file search, AXFR, InternetDB', /поиск забытых документов/.test(t) && /AXFR/.test(t) && /InternetDB/.test(t));
    ok('"Поиск забытых файлов на сайте" block with 6 modules', await ev(() => !!document.querySelector("#la-fz") && document.querySelectorAll("#la-fz .checkrow").length === 6));
    const est1 = await ev(() => document.querySelector("#la-fz-est").innerText);
    ok("estimate: requests and minutes", /запросов/.test(est1) && /мин/.test(est1), est1);
    await page.evaluate(() => document.querySelector("#la-fz").scrollIntoView()); await shot("launch_fuzz");
    await act("la-fz-mod", "vhost"); await wait(500);
    const est2 = await ev(() => document.querySelector("#la-fz-est").innerText);
    const pm = await ev(() => (FOCA.state.launch.fzEst || {}).per_module || {});
    ok("vhost enabled: estimate recomputed (per module)", pm.vhost > 0 && /запросов/.test(est2), [est2, pm]);
    ok("vhost in wizard modules", await ev(() => FOCA.state.launch.fzMods.includes("vhost")));
    await act("la-step", "fzRate:1:1:10"); await wait(400);
    ok("rate 6 req/s", await ev(() => FOCA.state.launch.fzRate === 6));
    // One-tap launch (no confirmation).
    t = await ev(() => FOCA.page().textContent);
    ok('wizard: "Поиск забытых файлов на сайте" block', /Поиск забытых файлов на сайте/.test(t));
    await act("la-start"); await wait(400);
    ok("scan started with one tap, active", await ev(() => FOCA.scan.running && FOCA.scan.active && FOCA.current() !== "/confirm-active"));
    // Up to the site search stage.
    // The demo timer is paused, so step manually (otherwise the scan would run on by itself).
    const step1 = () => ev(() => { FOCA.api.scan_resume(); window.FOCA_DEMO_BACKEND._ff(1); FOCA.api.scan_pause(); });
    await ev(() => FOCA.api.scan_pause());
    for (let i = 0; i < 60; i++) { const st = await ev(() => FOCA.api.scan_status()); if (st.stage === "fuzz") break; await step1(); }
    await step1(); await step1(); await ev(() => FOCA.api.scan_resume()); await ev(() => FOCA.api.scan_pause()); await wait(200);
    await ev(() => FOCA.go("/p/scan")); await wait(500);
    t = await txt();
    ok('"Поиск на сайте" stage on scan screen', /Поиск на сайте/.test(t));
    ok("brute-force counters: checked/found/filtered", /проверено/.test(t) && /найдено/.test(t) && /отфильтровано калибровкой/.test(t), t.slice(0, 400));
    ok('"Остановить перебор" button', await ev(() => !!document.querySelector('[data-act="scan-stop-fuzz"]')));
    await ev(() => document.querySelector("#scn-src-fuzz").scrollIntoView({ block: "center" })); await shot("scan_fuzz");
    await act("scan-stop-fuzz"); await wait(400);
    t = await txt();
    ok("brute force stopped by user, scan running", /Перебор остановлен пользователем/.test(t) && await ev(() => FOCA.scan.running), t.slice(0, 300));
    await ev(() => FOCA.api.scan_resume()); await ff(60); await wait(400);
    ok("scan finished", await ev(() => !FOCA.scan.running));
    // Findings.
    const fz = await ev(() => FOCA.db.findings.filter(f => f.module === "fuzz").map(f => [f.title, f.source]));
    ok('"Поиск на сайте" findings with Russian titles', fz.length >= 3 && fz.every(x => x[1] === "Поиск на сайте") && fz.some(x => /Открытый репозиторий \.git/.test(x[0])), fz);
    ok("no httpmap/vuln modules in findings", await ev(() => !FOCA.db.findings.some(f => ["httpmap", "vuln", "ports"].includes(f.module))));
    // Wordlists.
    await go("/settings/wordlists"); await wait(400);
    t = await txt();
    ok("wordlists: built-in, large, custom", /Встроенные/.test(t) && /Большие/.test(t) && /Свои/.test(t) && /quickhits/.test(t));
    await shot("wordlists");
    await act("wl-dl", "dns-top20000"); await wait(500);
    ok("large wordlist downloaded", await ev(() => FOCA.api.wordlists_list().then(d => d.items.find(x => x.id === "dns-top20000").downloaded)));
    await act("wl-import"); await wait(500);
    const sel = await ev(() => FOCA.db.settings.fuzz.wordlists);
    ok("custom wordlist imported and selected", sel.includes("custom:words_contoso.txt"), sel);
    ok("custom wordlist listed", /words_contoso\.txt/.test(await txt()));
    await act("wl-del", "custom:words_contoso.txt"); await wait(500);
    ok("custom wordlist deleted and deselected", !(await ev(() => FOCA.db.settings.fuzz.wordlists)).includes("custom:words_contoso.txt") && !/words_contoso\.txt/.test(await txt()));
    await act("wl-step", "rate:1:1:10"); await wait(200);
    ok("rate persists in settings", (await ev(() => FOCA.api.settings_get())).fuzz.rate === 6);
    // Report.
    await ev(() => Promise.all(FOCA.db.findings.filter(f => f.module === "fuzz").map(f => FOCA.api.finding_set_status(f.id, "confirmed"))));
    await go("/p/report-preview"); await wait(400);
    ok('report preview: "Найдено на сайте"', /Найдено на сайте|Знайдено на сайті/.test(await txt()));
    await ev(() => { const h = [...document.querySelectorAll(".rp-paper h2")].find(x => /Найдено на сайте|Знайдено на сайті/.test(x.textContent)); if (h) h.scrollIntoView(); }); await shot("report_site");
  } catch (e) { ok("exception", false, String(e && e.stack || e)); }
  fs.writeFileSync(`${out}/site_fuzz_steps.json`, JSON.stringify({ fails, log }, null, 1));
  log.forEach(l => console.log(l[0], l[1], l[0] === "FAIL" ? String(JSON.stringify(l[2])).slice(0, 400) : ""));
  if (fails) throw new Error(`${fails} FAIL`);
};
