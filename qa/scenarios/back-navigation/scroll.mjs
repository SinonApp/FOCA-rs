// Demo: Back (FOCA.back(), as MainActivity calls it, and browser history Back) returns to the previous
// screen at the scroll position the user left it; a newly opened screen starts at the top.
// Findings list → card → back, Overview → tab → back, Settings → sub-menu → back.
// qa/shoot.sh --routes none --out $PWD/qa/out/back-scroll --steps $PWD/qa/scenarios/back-navigation/scroll.mjs
import fs from "fs";
export default async (page, { out }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const top = () => ev(() => Math.round(FOCA.page().scrollTop));
  // Scrolls the page to the middle of its range (at least 200 px when possible) and returns the position.
  const scrollMid = () => ev(() => {
    const p = FOCA.page();
    p.scrollTop = Math.max(Math.min(200, p.scrollHeight - p.clientHeight), Math.round((p.scrollHeight - p.clientHeight) / 2));
    p.dispatchEvent(new Event("scroll"));
    return Math.round(p.scrollTop);
  });
  const androidBack = async () => { const v = await ev(() => FOCA.back()); await wait(900); return v; };
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    await ev(() => FOCA.reset(["/projects", "/p/overview"])); await wait(400);

    // Overview → Findings tab → back.
    const yo = await scrollMid();
    await ev(() => FOCA.tab("/p/findings")); await wait(500);
    ok("tab opens at the top", (await top()) === 0, await top());
    const yf = await scrollMid();
    ok("findings list is long enough to scroll", yf > 100, yf);

    // Findings list → card (forward starts at the top) → Android back.
    const fid = await ev(() => FOCA.db.findings[FOCA.db.findings.length - 1].id);
    await ev(id => FOCA.go("/p/finding/" + id), fid); await wait(500);
    ok("card opens at the top", (await top()) === 0, await top());
    let v = await androidBack();
    let y = await top();
    ok("back to the findings list restores the scroll", v === true && (await ev(() => FOCA.current())) === "/p/findings" && Math.abs(y - yf) <= 10, { v, y, yf });

    // Same through browser history (popstate), the path the system Back takes in a WebView without the bridge.
    await ev(id => FOCA.go("/p/finding/" + id), fid); await wait(500);
    await ev(() => history.back()); await wait(900);
    y = await top();
    ok("history back restores the scroll", (await ev(() => FOCA.current())) === "/p/findings" && Math.abs(y - yf) <= 10, { y, yf });

    v = await androidBack();
    y = await top();
    ok("tab → Overview restores the Overview scroll", v === true && (await ev(() => FOCA.current())) === "/p/overview" && Math.abs(y - yo) <= 10, { v, y, yo });

    // Settings → sub-menu → back.
    await ev(() => FOCA.reset(["/projects", "/settings"])); await wait(500);
    const ys = await scrollMid();
    await ev(() => FOCA.go("/settings/network")); await wait(500);
    ok("settings sub-menu opens at the top", (await top()) === 0, await top());
    v = await androidBack();
    y = await top();
    ok("back to Settings restores the scroll", v === true && (await ev(() => FOCA.current())) === "/settings" && Math.abs(y - ys) <= 10, { v, y, ys });

    // Re-opening the sub-menu after going back starts at the top again.
    await ev(() => { FOCA.page().scrollTop = 0; FOCA.go("/settings/network"); }); await wait(300);
    await scrollMid(); await androidBack();
    await ev(() => FOCA.go("/settings/network")); await wait(500);
    ok("a screen opened again starts at the top", (await top()) === 0, await top());
  } catch (e) { fails++; log.push(["FAIL", "exception", String((e && e.stack) || e).slice(0, 500)]); }
  fs.writeFileSync(`${out}/back_scroll_steps.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] ?? "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
