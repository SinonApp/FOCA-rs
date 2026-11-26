// Demo (wizard without a source list, sources in groups): Google removed; Startpage and Brave via the embedded browser
// in the wizard, on the sources screen and on the scan screen (statuses "Android only", "search engine check failed");
// key-based sources under the advanced (with key) group.
// qa/shoot.sh --routes /new,/settings/sources --out $PWD/qa/scenarios/search-engines --w 393 --theme dark --steps $PWD/qa/scenarios/search-engines/steps.mjs
import fs from "fs";
export default async (page, { out, prep, W, theme, errs, checkText }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const go = async r => { await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(250); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const act = async (a, arg) => { await ev(([a, arg]) => FOCA.actions[a](arg, document.querySelector(`[data-act="${a}${arg !== undefined ? ":" + arg : ""}"]`)), [a, arg]); await wait(250); };
  const tag = `${W}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/search_engines_${n}_${tag}.png` }); };
  const overflow = () => ev(() => document.documentElement.scrollWidth - innerWidth);
  try {
    await go("/projects"); await ev(() => FOCA.api.demo_reset()); await wait(200);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(200);
    // Wizard.
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go("/new"); }); await wait(400);
    // The wizard shows a single "N keyless sources" line with no "set" buttons.
    let t = await txt();
    ok("wizard: no Google", !/Google CSE|gcse/i.test(t));
    ok('wizard: "источников без ключей" line with Startpage and Brave', /источник\S*\s+без ключей/.test(t) && /Startpage/.test(t) && /Brave/.test(t), t.match(/Источники.{0,300}/s)?.[0]);
    ok('wizard: no "Указать"', !/Указать/.test(t));
    await ev(() => { const h = [...document.querySelectorAll(".page h3")].find(x => /^Источники/.test(x.textContent)); if (h) h.scrollIntoView(); });
    await shot("launch_sources");
    ok("wizard: no horizontal overflow", (await overflow()) <= 1);
    await checkText("search-engines /new");
    // Passive launch: startpage and brave_web are among the default scan sources.
    await act("la-prof", "passive"); await wait(300);
    await act("la-start"); await wait(500);
    await ev(() => FOCA.api.scan_pause()); await wait(200);
    const ids = await ev(() => FOCA.scan.sources.map(s => s.id));
    ok("scan: startpage and brave_web among sources", ids.includes("startpage") && ids.includes("brave_web"), ids);
    ok("scan: no gcse", !ids.includes("gcse"));
    // Statuses sent by the core: unavailable (no WebView) and blocked with a reason.
    await ev(() => FOCA.go("/p/scan")); await wait(400);
    await ev(() => {
      const sp = FOCA.scan.sources.find(x => x.id === "startpage"), br = FOCA.scan.sources.find(x => x.id === "brave_web");
      Object.assign(sp, { status: "blocked", error: "капча / заблокировано: проверка поисковика не пройдена" });
      Object.assign(br, { status: "unavailable", error: "нужен WebView (только в Android)" });
      FOCA.render(true);
    }); await wait(300);
    const spT = await ev(() => document.querySelector("#scn-src-startpage")?.textContent || "");
    const brT = await ev(() => document.querySelector("#scn-src-brave_web")?.textContent || "");
    ok('scan: Startpage, "Проверка поисковика не пройдена"', /Проверка поисковика не пройдена/.test(spT), spT.slice(0, 160));
    ok('scan: Brave, "Только в Android"', /Только в Android/.test(brT) && /встроенный браузер/.test(brT), brT.slice(0, 160));
    await ev(() => document.querySelector("#scn-src-startpage")?.scrollIntoView({ block: "center" }));
    await shot("scan_sources");
    ok("scan: no horizontal overflow", (await overflow()) <= 1);
    await checkText("search-engines /p/scan");
    await ev(() => FOCA.api.scan_stop && FOCA.api.scan_stop({ reason: "user" })); await wait(300);
    // Settings → Sources.
    await go("/settings/sources"); await wait(300);
    await ev(() => { FOCA.state.srcOpen.search = true; FOCA.state.srcOpen.key = true; FOCA.render(true); }); await wait(300); // expand the groups
    t = await txt();
    ok("sources: Startpage and Brave via browser", /Startpage \(через браузер\)/.test(t) && /Brave Search \(через браузер\)/.test(t));
    ok('sources: "Дополнительно, с ключом" and Brave API', /Дополнительно, с ключом/.test(t) && /Brave Search API/.test(t));
    ok("sources: no Google CSE", !/Google CSE/.test(t));
    await ev(() => document.querySelector('[data-src="startpage"]')?.scrollIntoView({ block: "center" }));
    await shot("settings_sources");
    ok("sources: no horizontal overflow", (await overflow()) <= 1);
    // Keys.
    await go("/settings/keys"); await wait(300);
    t = await txt();
    ok("keys: no Google CSE, Brave API optional", !/Google/.test(t) && /Brave Search API/.test(t));
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/search_engines_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
