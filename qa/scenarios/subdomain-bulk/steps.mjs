// Demo: bulk "add to scope and scan" of out-of-scope subdomains on /p/out-of-scope. Narrows the contoso
// scope to its apex URL so subdomains become candidates, selects all subdomains of the main domain with one
// action, checks the confirmation sheet (CDN/cloud addresses held out of the port scan, the Full profile
// requires the authorization checkbox), confirms and expects the names in the scope and a scan of only them.
// qa/shoot.sh --routes none --out $PWD/qa/out/subdomain-bulk --w 393 --steps $PWD/qa/scenarios/subdomain-bulk/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(250); await page.screenshot({ path: `${out}/sbulk_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const clickAct = act => ev(a => { const b = document.querySelector(`[data-act="${a}"]`); if (b) b.dispatchEvent(new MouseEvent("click", { bubbles: true })); return !!b; }, act);
  const sheetTxt = () => ev(() => (document.querySelector(".sheet.show") || {}).textContent || "");
  const goDisabled = () => ev(() => { const b = document.getElementById("oos-bgo"); return b ? b.disabled : null; });
  const errs = []; page.on("pageerror", e => errs.push(e.message));
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(300);
    // only the apex URL stays in scope: every subdomain becomes an out-of-scope candidate
    await ev(() => FOCA.api.scope_set({ targets: [{ v: "https://contoso.example/", type: "url" }] })); await wait(200);

    await go("/p/out-of-scope");
    let t = await txt();
    ok("bulk bar is shown on the new tab", !!(await ev(() => document.querySelector(".scn-bulk"))), t.slice(0, 160));
    ok("subdomain candidates listed", /cdn\.contoso\.example/.test(t) && /dev\.contoso\.example/.test(t), t.slice(0, 200));
    ok("excluded name has no pick box", !(await ev(() => [...document.querySelectorAll(".scn-oos")].some(c => /mail\.contoso\.example/.test(c.textContent) && c.querySelector(".scn-opick")))));
    ok("go button disabled without a selection", await ev(() => document.querySelector('[data-act="oos-bulk"]').disabled));
    ok("select-all button", await clickAct("oos-sel-all")); await wait(200);
    const sel = await ev(() => FOCA.state.oosSel.slice());
    ok("all subdomains of the main domain selected", sel.length >= 8 && sel.every(h => h.endsWith(".contoso.example")) && !sel.includes("mail.contoso.example"), sel);
    ok("selection count in the bar", new RegExp(`выбрано ${sel.length}`).test(await txt()));
    if (overflow) { const v = await overflow(); ok("out-of-scope: no horizontal overflow", v <= 1, v); }
    await shot("selected");
    // single toggle
    const first = await ev(() => FOCA.db.oos.find(o => o.host === "dev.contoso.example").id);
    await clickAct(`oos-sel:${first}`); await wait(150);
    ok("toggle removes one name", !(await ev(() => FOCA.state.oosSel.includes("dev.contoso.example"))));
    await clickAct(`oos-sel:${first}`); await wait(150);

    ok("open confirmation", await clickAct("oos-bulk")); await wait(350);
    let s = await sheetTxt();
    ok("sheet lists the names to add", /Будут добавлены в скоуп: \d+/.test(s) && /cdn\.contoso\.example/.test(s), s.slice(0, 200));
    ok("sheet lists CDN/cloud addresses held out of the port scan", /Без скана портов/.test(s) && /192\.0\.2\.150/.test(s) && /Cloudflare/.test(s) && /198\.51\.100\.144/.test(s), s.slice(0, 400));
    ok("standard profile by default, button enabled", (await goDisabled()) === false);
    await shot("sheet");
    await clickAct("oos-bprof:full"); await wait(250);
    s = await sheetTxt();
    ok("full profile asks for the authorization", /разрешение владельцев на активную проверку/.test(s) && (await goDisabled()) === true, s.slice(-200));
    await clickAct("oos-bcons"); await wait(100);
    ok("consent enables the button", (await goDisabled()) === false);
    await shot("sheet_full");
    await clickAct("oos-bprof:std"); await wait(250);
    ok("back to standard", (await goDisabled()) === false);
    const scope0 = await ev(() => FOCA.db.scope.targets.length);
    ok("confirm", await clickAct("oos-bulk-go")); await wait(700);
    const scope1 = await ev(() => FOCA.db.scope.targets.map(t => t.v));
    ok("names added to the scope", scope1.length === scope0 + sel.length && scope1.includes("cdn.contoso.example"), scope1);
    const run = await ev(() => FOCA.api.scan_status());
    ok("scan of only the added names started", run && run.running && (run.targets || []).length === sel.length && (run.targets || []).every(h => sel.includes(h)), run && { running: run.running, targets: run.targets });
    ok("selection cleared", (await ev(() => FOCA.state.oosSel.length)) === 0);
    await ev(() => FOCA.api.scan_stop("user")); await wait(300);
    await go("/p/out-of-scope"); await ev(() => FOCA.actions["oos-tab"]("scope")); await wait(250);
    ok("added candidates move to the Added tab", /cdn\.contoso\.example/.test(await txt()));
    await shot("added");
    ok("no page errors", !errs.length, errs.slice(0, 3));
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/sbulk_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
