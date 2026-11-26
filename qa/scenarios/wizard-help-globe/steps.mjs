// Demo: wizard without "set" buttons and sources in groups, numeric inputs with a recommendation and presets,
// the offline help section, the 3D globe on /p/map.
// qa/shoot.sh --routes /p/overview --out $PWD/qa/scenarios/wizard-help-globe --w 393 --theme dark --steps $PWD/qa/scenarios/wizard-help-globe/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme, checkText }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/wizard_help_globe_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const noOvf = async n => ok(`${n}: no horizontal overflow`, (await overflow()) <= 1, await overflow());
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    // Wizard: a single sources line, no "set" buttons.
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go("/new"); }); await wait(450);
    if (!(await ev(() => FOCA.state.launch.adv))) await ev(() => FOCA.actions["la-adv"]());
    await wait(300);
    let t = await txt();
    ok('wizard: no "Указать" buttons or "Нужен ключ" badges', !/Указать|Нужен ключ/.test(t) && !(await ev(() => !!document.querySelector('[data-act^="la-key"]'))));
    ok('wizard: "N источников без ключей" line → sources', /\d+\s*источник\S*\s+без ключей/.test(t) && await ev(() => !!document.querySelector('[data-act="go:/settings/sources"]')), t.match(/Источники.{0,120}/s)?.[0]);
    await ev(() => document.querySelector(".la-srcs")?.scrollIntoView({ block: "center" })); await shot("new_sources");
    await noOvf("wizard");
    // The wizard still sends only disabled sources: paid ones without a key go to sources_off.
    await ev(() => FOCA.api.key_delete("shodan")); await wait(100);
    const off = await ev(() => { let got = null; const orig = FOCA.actions["scan-start"]; FOCA.actions["scan-start"] = o => { got = o; return Promise.reject(new Error("stub")); }; FOCA.actions["la-start"](); FOCA.actions["scan-start"] = orig; return got && got.sources_off; });
    ok("wizard: sources_off has the paid keyless source and no free ones", Array.isArray(off) && off.includes("shodan") && !off.includes("wayback") && !off.includes("startpage"), off);
    // Out-of-range number in the wizard (threads are shared with the network settings).
    await page.fill("#nf-la-net-threads", "500"); await page.press("#nf-la-net-threads", "Enter"); await wait(250);
    ok('wizard: 500 threads → hint "Максимум 64"', /Максимум 64/.test(await ev(() => document.querySelector("#nf-la-net-threads-e")?.textContent || "")));
    await page.fill("#nf-la-net-threads", "6"); await page.press("#nf-la-net-threads", "Enter"); await wait(300);
    // Sources: 5 groups + "advanced, with key".
    await go("/settings/sources");
    t = await txt();
    ok("sources: 5 groups", ["Поисковики", "Архивы", "Поддомены", "Разведка", "Краулер"].every(g => t.includes(g)), t.slice(0, 200));
    ok('sources: collapsed "Дополнительно, с ключом", no "Указать"', /Дополнительно, с ключом/.test(t) && !/Указать/.test(t) && !/Brave Search API/.test(t));
    await ev(() => FOCA.actions["src-g"]("arch")); await wait(250);
    ok("sources: group master toggle disables all archives", await ev(() => ["wayback", "cc", "arquivo"].every(id => FOCA.db.settings.sources[id].enabled === false)));
    await ev(() => FOCA.actions["src-g"]("arch")); await wait(250);
    await ev(() => FOCA.actions["src-open"]("search")); await wait(250);
    ok("sources: expanding shows Startpage…Bing", /Startpage/.test(await txt()) && /Bing/.test(await txt()));
    await shot("sources");
    await noOvf("sources");
    await ev(() => FOCA.actions["src-open"]("search"));
    // Scan: paid sources without a key are hidden.
    await ev(() => FOCA.actions["scan-start"]({ profile: "std", open: true })); await wait(500);
    await ev(() => FOCA.api.scan_pause && FOCA.api.scan_pause()); await wait(200);
    await go("/p/scan");
    ok('scan: Shodan without key not shown, no "Указать ключ"', await ev(() => !document.querySelector("#scn-src-shodan") && !/Указать ключ|Нет ключа/.test(FOCA.page().textContent)));
    await ev(() => FOCA.api.scan_stop && FOCA.api.scan_stop({ reason: "user" })); await wait(300);
    // Adding a key enables the source automatically.
    await ev(() => FOCA.api.settings_set({ sources: { shodan: { enabled: false } } })); await wait(100);
    await ev(() => FOCA.openKeySheet("shodan")); await wait(400);
    await page.fill("#st-kv", "shodan_demo_key_1234567890");
    await ev(() => [...document.querySelectorAll(".sheet.show .sh-f .btn")].pop().click()); await wait(500);
    ok("key added → source enabled", await ev(() => FOCA.db.settings.sources.shodan.enabled === true));
    // Network: numeric input, presets.
    await go("/settings/network");
    await ev(() => document.querySelector("#st-presets")?.scrollIntoView({ block: "start" }));
    await page.fill("#nf-net-threads", "999"); await page.press("#nf-net-threads", "Enter"); await wait(250);
    const err = await ev(() => document.querySelector("#nf-net-threads-e")?.textContent || "");
    ok("network: 999 threads → highlight and reason, value not saved", /Максимум 64/.test(err) && await ev(() => document.querySelector('.nf[data-nf="net-threads"]').classList.contains("bad")) && await ev(() => FOCA.db.settings.net.threads !== 999), err);
    await shot("net_error");
    await page.fill("#nf-net-threads", "12"); await page.locator("#nf-net-rps").focus(); await wait(250);
    ok("network: 12 threads applied on blur", await ev(() => +FOCA.db.settings.net.threads === 12));
    await ev(() => FOCA.actions["st-preset"]("soft")); await wait(300);
    ok('network: "Бережно" preset = 2 / 3 / 30', await ev(() => { const n = FOCA.db.settings.net; return +n.threads === 2 && +n.rps === 3 && +n.timeout === 30; }));
    await ev(() => FOCA.actions["st-preset"]("fast")); await wait(300);
    ok('network: "Быстро" preset = 16 / 20 / 10 and highlighted', await ev(() => { const n = FOCA.db.settings.net; return +n.threads === 16 && +n.rps === 20 && +n.timeout === 10 && /Быстро/.test(document.querySelector("#st-presets .on")?.textContent || ""); }));
    await ev(() => FOCA.actions["nf-step"]("net-threads:1")); await wait(200);
    ok('network: "+" changes the value', await ev(() => +FOCA.db.settings.net.threads === 17));
    ok("network: settings have ⓘ icon → article", await ev(() => !!document.querySelector('.nf[data-nf="net-rps"] [data-act="go:/help/set-rps"]')));
    await ev(() => FOCA.actions["st-preset"]("normal")); await wait(300);
    await ev(() => document.querySelector("#st-presets")?.scrollIntoView({ block: "start" })); await shot("net");
    await noOvf("network");
    // Wordlists: numeric input.
    await go("/settings/wordlists");
    await page.fill("#nf-wl-rate", "0"); await page.press("#nf-wl-rate", "Enter"); await wait(250);
    ok('wordlists: rate 0 → "Минимум 1"', /Минимум 1/.test(await ev(() => document.querySelector("#nf-wl-rate-e")?.textContent || "")));
    await page.fill("#nf-wl-rate", "5"); await page.press("#nf-wl-rate", "Enter"); await wait(200);
    // Help.
    await go("/settings");
    ok('settings: "Помощь" link', /Помощь/.test(await txt()));
    await go("/help");
    await shot("help");
    await noOvf("help");
    await page.fill("#hl-q", "капча"); await wait(300);
    const res = await ev(() => document.querySelector("#hl-res")?.textContent || "");
    ok('help: searching "капча" finds the article', /Источник пишет «капча»/.test(res), res.slice(0, 160));
    await page.fill("#hl-q", ""); await wait(150);
    for (const id of ["background", "profiles", "glossary"]) { await go("/help/" + id); await noOvf("help/" + id); }
    ok("help: glossary ≥ 30 terms", await ev(() => document.querySelectorAll(".hl-gl dt").length >= 30));
    await go("/help/background"); await shot("help_article");
    await checkText("wizard-help-globe /help");
    // Globe.
    await go("/p/map"); await wait(900);
    const drawn = await ev(() => { const c = document.querySelector("#v2m-cv"); if (!c) return 0; const d = c.getContext("2d").getImageData(c.width / 2 - 20, c.height / 2 - 20, 40, 40).data; let s = 0; for (let i = 0; i < d.length; i += 4) s += d[i] + d[i + 1] + d[i + 2]; return s; });
    ok("globe: canvas drawn (not empty)", drawn > 1000, drawn);
    const z0 = await ev(() => FOCA.state.v2.m3g.z);
    await page.click('[data-act="v2m-z:in"]'); await wait(500);
    const z1 = await ev(() => FOCA.state.v2.m3g.z);
    ok('globe: "+" zooms in', z1 > z0 * 1.4, [z0, z1]);
    await page.click('[data-act="v2m-z:out"]'); await wait(500);
    ok('globe: "−" zooms out', (await ev(() => FOCA.state.v2.m3g.z)) < z1);
    await ev(() => { const G = FOCA.db.gps; const i = G.findIndex(g => G.filter(x => Math.abs(x.lat - g.lat) < 0.05 && Math.abs(x.lon - g.lon) < 0.05).length === 1); FOCA.state.v2.m3g.flyTo([Math.max(0, i)], 30); }); await wait(1100);
    const h = await ev(() => FOCA.state.v2.m3g.hits.find(x => x.n === 1));
    const cb = await page.locator("#v2m-cv").boundingBox();
    if (h) await page.mouse.click(cb.x + h.x, cb.y + h.y); await wait(400);
    ok("globe: tapping a point opens a card with coordinates", await ev(() => { const c = document.querySelector("#v2m-selc"); return !!c && /°.*N/.test(c.textContent) && /Документ/.test(c.textContent) && /Копировать/.test(c.textContent); }), h);
    await shot("map_point");
    await ev(() => FOCA.actions["v2m-z"]("fit")); await wait(900); await shot("map");
    await noOvf("globe");
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/wizard_help_globe_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
