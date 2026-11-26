// Demo: Back via FOCA.back() as on Android (MainActivity → evaluateJavascript): the chain
// sheet → card → list → overview → project list → false (only then is the app moved to the background);
// terms of use / lock screen return false (move to background, not "decline").
// qa/shoot.sh --routes /p/overview --out qa/scenarios/back-navigation --steps $PWD/qa/scenarios/back-navigation/steps.mjs
import fs from "fs";
export default async (page, { out, prep }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const go = async r => { await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(250); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  // As on Android: the FOCA.back() result and the route after it.
  const back = async () => { const r = await ev(() => { const v = FOCA.back(); return { v, cur: FOCA.current(), sheet: !!document.querySelector(".sheet.show") }; }); await wait(300); return r; };
  try {
    await go("/projects"); await ev(() => FOCA.api.demo_reset()); await wait(300);
    await go("/projects");
    ok("start: project list", await ev(() => FOCA.current()) === "/projects", await ev(() => FOCA.current()));
    const fid = await ev(() => FOCA.db.findings[0].id);
    await ev(() => FOCA.go("/p/overview")); await wait(200);
    await ev(() => FOCA.tab("/p/findings")); await wait(200);
    await ev(id => FOCA.go("/p/finding/" + id), fid); await wait(200);
    await ev(() => FOCA.actions.menu()); await wait(300);
    ok("menu sheet opened on the card", await ev(() => !!document.querySelector(".sheet.show")));
    let r = await back(); ok("1: sheet closed, stayed on the card", r.v === true && !r.sheet && r.cur === "/p/finding/" + fid, r);
    r = await back(); ok("2: card → findings list", r.v === true && r.cur === "/p/findings", r);
    r = await back(); ok("3: list (tab) → Overview", r.v === true && r.cur === "/p/overview", r);
    r = await back(); ok("4: Overview → project list", r.v === true && r.cur === "/projects", r);
    r = await back(); ok("5: project list → false (minimize)", r.v === false && r.cur === "/projects", r);
    // Deep link (notification): a single-screen stack goes to the logical parent instead of backgrounding.
    await go("/p/data"); 
    r = await back(); ok('deep link: "Данные" tab → Overview', r.v === true && r.cur === "/p/overview", r);
    r = await back(); ok("→ project list", r.v === true && r.cur === "/projects", r);
    await go("/settings/network");
    r = await back(); ok("settings/network → settings", r.v === true && r.cur === "/settings", r);
    r = await back(); ok("settings → projects", r.v === true && r.cur === "/projects", r);
    // Terms of use: Back moves to background (false) instead of declining.
    await ev(() => FOCA.reset(["/terms"])); await wait(300);
    const before = await ev(() => FOCA.current());
    r = await back(); ok("terms screen → false, stays on terms", before === "/terms" && r.v === false && r.cur === "/terms", { before, r });
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e).slice(0, 500)]); }
  try { fs.writeFileSync(`${out}/back_navigation_steps.json`, JSON.stringify({ ok: log.length - fails, fail: fails, log }, null, 1)); } catch (e) {}
  console.error(log.map(l => `${l[0]} ${l[1]}${l[0] === "FAIL" ? " " + JSON.stringify(l[2] ?? "").slice(0, 400) : ""}`).join("\n"));
  console.error(`back-navigation: ${log.length - fails} OK, ${fails} FAIL`);
};
