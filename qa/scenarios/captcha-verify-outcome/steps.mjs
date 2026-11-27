// Demo: outcome of the manual search engine check. Only "done" marks the engine verified and asks the
// core to retry it; cancelled (Cancel, Back, swipe, app left), failed (page did not load) and
// not_solved (Done while the captcha is still shown) leave it blocked with a short snack and the
// "Pass the check" button. Covers the single-source button, the "verify all" queue and Settings →
// Network → prepare search engines, in RU and EN.
// qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/captcha-verify-outcome/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const snack = () => ev(() => document.querySelector("#snack")?.textContent || "");
  // Every platform_verify_search call goes to the demo backend with the chosen outcome; retries are counted.
  const setOutcome = states => ev(st => {
    window.__vq = st.slice(); window.__vs = []; window.__retries = [];
    if (!window.__vOrig) {
      window.__vOrig = FOCA.api.platform_verify_search;
      window.__rOrig = FOCA.api.scan_retry_source;
      FOCA.api.platform_verify_search = a => { window.__vs.push(a.url); return window.__vOrig({ ...a, demo_state: window.__vq.length ? window.__vq.shift() : "done" }); };
      FOCA.api.scan_retry_source = id => { window.__retries.push(id); return window.__rOrig(id); };
    }
  }, states);
  const blockEngines = ids => ev(ids => {
    const S = FOCA.scan.sources;
    for (const id of ids) {
      let s = S.find(x => x.id === id);
      if (!s) { s = { id, name: id }; S.push(s); }
      Object.assign(s, { status: "blocked", n: 0, error: "капча / заблокировано: поисковик показал капчу", verifyUrl: id === "mojeek" ? "https://www.mojeek.com/search?q=foca" : "https://www.startpage.com/", retryAsked: false, verifyDone: false });
    }
    FOCA.render(true);
  }, ids);
  const state = id => ev(id => {
    const s = FOCA.scan.sources.find(x => x.id === id);
    return { verifyDone: !!s.verifyDone, retryAsked: !!s.retryAsked, btn: !!document.querySelector(`[data-act="scan-verify-src:${id}"]`), retries: window.__retries.slice(), calls: window.__vs.length };
  }, id);
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);

    // Pure mapping of the reply: only an explicit "done" counts; a reply without state is never success.
    const m = await ev(() => [
      FOCA.verifyState({ state: "done", ok: true }), FOCA.verifyState({ state: "cancelled", ok: false }),
      FOCA.verifyState({ state: "failed" }), FOCA.verifyState({ state: "not_solved" }),
      FOCA.verifyState({ ok: true, closed: true }), FOCA.verifyState({ ok: false, unsupported: true }), FOCA.verifyState(null),
    ]);
    ok("verifyState mapping", JSON.stringify(m) === JSON.stringify(["done", "cancelled", "failed", "not_solved", "cancelled", "unsupported", "unsupported"]), m);

    for (const lang of ["ru", "en"]) {
      await ev(l => FOCA.i18n.setLang(l), lang); await wait(300);
      await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "passive" })); await wait(300);
      await ev(() => FOCA.api.scan_pause()); await ev(() => FOCA.go("/p/scan")); await wait(400);
      const want = {
        cancelled: lang === "en" ? /check cancelled/ : /проверка отменена/,
        failed: lang === "en" ? /did not load/ : /не загрузилась/,
        not_solved: lang === "en" ? /still shows a captcha/ : /всё ещё показывает капчу/,
      };
      // Single source: every non-done outcome keeps the engine blocked and the button in place.
      for (const st of ["cancelled", "failed", "not_solved"]) {
        await blockEngines(["startpage"]); await setOutcome([st]);
        await ev(() => document.querySelector('[data-act="scan-verify-src:startpage"]')?.click()); await wait(500);
        const s = await state("startpage");
        ok(`${lang}: ${st} does not mark verified nor retry`, s.calls === 1 && !s.verifyDone && !s.retryAsked && s.retries.length === 0, s);
        ok(`${lang}: ${st} keeps the 'Pass the check' button`, s.btn, s);
        const sn = await snack();
        ok(`${lang}: ${st} snack`, want[st].test(sn) && (lang !== "en" || !/[а-яё]/i.test(sn)), sn);
      }
      // Done: verified and retried in this scan.
      await blockEngines(["startpage"]); await setOutcome(["done"]);
      await ev(() => document.querySelector('[data-act="scan-verify-src:startpage"]')?.click()); await wait(500);
      let s = await state("startpage");
      // A granted retry restarts the source (its "running" event clears verifyDone), so either flag proves it.
      ok(`${lang}: done marks verified and asks the core to retry`, (s.verifyDone || s.retryAsked) && !s.btn && s.retries.join() === "startpage", s);
      if (lang === "ru") await page.screenshot({ path: `${out}/captcha-verify-outcome_done_${tag}.png` });
      // Badge and status line agree: a retry granted after "done" reads "queued again", never
      // "needs verification"; a new captcha on the re-poll brings the warning back.
      const row = id => ev(id => { const r = document.getElementById(`scn-src-${id}`); return r ? { pill: r.querySelector(".scn-srh .pill")?.textContent.trim() || "", sub: r.querySelector(".s")?.textContent.trim() || "", btn: !!r.querySelector('[data-act^="scan-verify-src:"]') } : null; }, id);
      await ev(() => { const s = FOCA.scan.sources.find(x => x.id === "startpage"); Object.assign(s, { status: "blocked", verifyUrl: "https://www.startpage.com/", verifyDone: true, retryAsked: true }); FOCA.render(true); }); await wait(250);
      let r = await row("startpage");
      const qd = lang === "en" ? /Queued again/ : /Снова в очереди/, nv = lang === "en" ? /Check needed/i : /Нужна проверка/;
      ok(`${lang}: after done the badge says queued again, matching the status line`, !!r && qd.test(r.pill) && !nv.test(r.pill) && !r.btn && (lang === "en" ? /passed/i : /пройдена/).test(r.sub), r);
      await ev(() => { FOCA.emit("scan", { type: "source", id: "startpage", name: "Startpage", status: "running" }); FOCA.emit("scan", { type: "source", id: "startpage", name: "Startpage", status: "blocked", error: "капча / заблокировано: поисковик показал капчу", verify_url: "https://www.startpage.com/" }); FOCA.render(true); }); await wait(250);
      r = await row("startpage");
      ok(`${lang}: a captcha on the re-poll shows 'needs verification' again with the button`, !!r && nv.test(r.pill) && r.btn, r);

      // Verify all: Cancel on the first engine stops the queue and verifies nothing.
      await blockEngines(["startpage", "mojeek"]); await setOutcome(["cancelled"]);
      await ev(() => document.querySelector('[data-act="scan-verify-all"]')?.click()); await wait(800);
      const q = await ev(() => ({ calls: window.__vs.slice(), retries: window.__retries.slice(), done: FOCA.scan.sources.filter(x => x.verifyDone).map(x => x.id), banner: !!document.querySelector('[data-act="scan-verify-all"]') }));
      ok(`${lang}: verify all stops on Cancel without verifying`, q.calls.length === 1 && q.retries.length === 0 && q.done.length === 0 && q.banner, q);
      ok(`${lang}: verify all cancel snack`, want.cancelled.test(await snack()), await snack());
      // Verify all: an unsolved first engine does not stop the second one.
      await blockEngines(["startpage", "mojeek"]); await setOutcome(["not_solved", "done"]);
      await ev(() => document.querySelector('[data-act="scan-verify-all"]')?.click()); await wait(800);
      const q2 = await ev(() => ({ calls: window.__vs.length, retries: window.__retries.slice(), done: FOCA.scan.sources.filter(x => x.verifyDone).map(x => x.id) }));
      ok(`${lang}: verify all: only the solved engine is verified`, q2.calls === 2 && q2.done.join() === "mojeek" && !q2.retries.includes("startpage"), q2);
      ok(`${lang}: verify all names the unsolved engine`, want.not_solved.test(await snack()), await snack());
      await ev(() => FOCA.api.scan_stop({ reason: "user" })); await wait(300);

      // Settings → Network → prepare search engines.
      await ev(() => FOCA.go("/settings/network")); await wait(450);
      await setOutcome(["done", "cancelled"]);
      await ev(() => document.querySelector('[data-act="st-prep-engines"]')?.click()); await wait(700);
      let calls = await ev(() => window.__vs.length);
      ok(`${lang}: preparation stops on Cancel`, calls === 2 && (lang === "en" ? /stopped\. Search engines prepared: 1/ : /прервана\. Подготовлено поисковиков: 1/).test(await snack()), [calls, await snack()]);
      await setOutcome(["done", "done", "not_solved", "done"]);
      await ev(() => document.querySelector('[data-act="st-prep-engines"]')?.click()); await wait(700);
      calls = await ev(() => window.__vs.length);
      ok(`${lang}: preparation counts only solved engines`, calls === 4 && (lang === "en" ? /3 of 4.*Yahoo/ : /3 из 4.*Yahoo/).test(await snack()), [calls, await snack()]);
      await setOutcome([]);
      await ev(() => document.querySelector('[data-act="st-prep-engines"]')?.click()); await wait(700);
      ok(`${lang}: preparation all solved`, (lang === "en" ? /prepared: 4/ : /подготовлено: 4/).test(await snack()), await snack());
    }
  } catch (e) { fails++; log.push(["FAIL", "exception", String((e && e.stack) || e)]); }
  fs.writeFileSync(`${out}/captcha-verify-outcome_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
