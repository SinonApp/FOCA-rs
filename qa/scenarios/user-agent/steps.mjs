// Demo: Settings → Network → User-Agent: the profiles (auto fresh Chrome, Chrome Android, Firefox, Safari,
// honest FOCA-rs, custom), the resulting string, and compatibility with legacy values (chrome, foca, random).
// qa/shoot.sh --routes none --out $PWD/qa/scenarios/user-agent --w 393 --theme dark --steps $PWD/qa/scenarios/user-agent/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const fin = () => ev(() => document.querySelector("#st-uafinal")?.textContent || "");
  const titles = () => ev(() => [...document.querySelectorAll("#st-ualist .t")].map(x => x.textContent));
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/user_agent_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  // Expected Chrome major version by date (same model as foca-net::ua).
  const chromeNow = () => { const an = [[133, "2025-02-04", 28], [145, "2026-01-28", 28], [152, "2026-08-12", 14]]; const t = Date.now(); let a = an[0]; an.forEach(x => { if (Date.parse(x[1]) <= t) a = x; }); return a[0] + Math.floor((t - Date.parse(a[1])) / 864e5 / a[2]); };
  const set = v => ev(v => FOCA.actions["st-set"]("net.ua:" + v), v);
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await wait(150);
    await go("/settings/network");
    await ev(() => document.querySelector("#st-ualist")?.scrollIntoView({ block: "center" })); await wait(200);
    const t = await titles();
    ok("6 profiles in the right order", t.length === 6 && /^Авто: свежий Chrome \d+ · Windows$/.test(t[0]) && /Chrome \d+ · Android/.test(t[1]) && /^Firefox \d+/.test(t[2]) && /^Safari/.test(t[3]) && /Честный FOCA-rs/.test(t[4]) && t[5] === "Свой", t);
    ok('legacy ua: \"chrome\" = "Авто", final string: fresh Chrome by date', (await ev(() => document.querySelector("#st-ualist .on .t")?.textContent || "")).startsWith("Авто") && (await fin()).includes(`Chrome/${chromeNow()}.0.0.0 Safari/537.36`) && (await fin()).includes("Windows NT 10.0"), await fin());
    ok("hint about consistent headers (Sec-CH-UA for Chrome)", await ev(() => /Sec-CH-UA/.test(document.querySelector("#st-uafinal")?.parentElement?.textContent || "")));
    await shot("ua_auto");
    await set("firefox"); await wait(300);
    ok("Firefox: rv matches version, no Sec-CH-UA in hint", /rv:(\d+)\.0\) Gecko\/20100101 Firefox\/\1\.0$/.test(await fin()) && !(await ev(() => /Sec-CH-UA/.test(document.querySelector("#st-uafinal")?.parentElement?.textContent || ""))), await fin());
    ok("core receives ua=firefox", await ev(() => (FOCA.db.settings.net || {}).ua === "firefox"));
    await set("chrome_android"); await wait(300);
    ok("Chrome Android: Mobile Safari, same version", (await fin()).includes(`Chrome/${chromeNow()}.0.0.0 Mobile Safari`), await fin());
    await set("safari"); await wait(300);
    ok("Safari: Version/N.0 Safari/605.1.15", /Version\/\d+\.\d Safari\/605\.1\.15$/.test(await fin()), await fin());
    await set("honest"); await wait(300);
    ok("Honest: FOCA-rs/<version>", /^FOCA-rs\/\S+$/.test(await fin()), await fin());
    await set("custom"); await wait(300);
    await page.fill("#st-uac", "MyAudit/1.0"); await wait(200);
    ok("Custom: string is typed and shown immediately", (await fin()) === "MyAudit/1.0", await fin());
    await shot("ua_custom");
    // Legacy values: foca → honest, random → auto.
    await ev(() => { FOCA.state.settings.net.ua = "foca"; FOCA.render(true); }); await wait(300);
    ok('legacy foca → "Честный FOCA-rs"', /Честный/.test(await ev(() => document.querySelector("#st-ualist .on .t")?.textContent || "")) && (await fin()).startsWith("FOCA-rs/"), await fin());
    await ev(() => { FOCA.state.settings.net.ua = "random"; FOCA.render(true); }); await wait(300);
    ok('legacy random → "Авто"', (await ev(() => document.querySelector("#st-ualist .on .t")?.textContent || "")).startsWith("Авто"));
    // A fresh version cache from the core takes precedence over the estimate.
    await ev(() => { FOCA.state.settings.net.ua = "chrome"; FOCA.db.settings.net.ua_versions = { chrome: 777, fetched: Math.floor(Date.now() / 1000) - 60 }; FOCA.render(true); }); await wait(300);
    ok("fresh net.ua_versions → version from cache", (await fin()).includes("Chrome/777.0.0.0"), await fin());
    ok("no horizontal overflow", (await overflow()) <= 1, await overflow());
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/user_agent_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
