// Deleting one scan (history sheet, stopped card, paused scan) and reference cases kept out of
// recent projects (demo backend).
// qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/scan-delete/steps.mjs [--w 360 --theme light --fs 2]
export default async (page, { W, fsc, theme, out, prep }) => {
  let fails = 0,
    oks = 0;
  const ok = (name, cond, data) => {
    if (cond) oks++;
    else fails++;
    console.log(
      `${cond ? "OK  " : "FAIL"} ${name}${!cond && data !== undefined ? " - " + JSON.stringify(data) : ""}`,
    );
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => {
    await ev(r => FOCA.go(r), r);
    await wait(450);
  };
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => {
    await wait(250);
    await page.screenshot({ path: `${out}/scan-delete_${n}_${tag}.png` });
  };
  const overflow = () =>
    ev(() => {
      const p = FOCA.page() || document.body;
      const sh = document.querySelector(".sheet.show");
      return Math.max(
        document.documentElement.scrollWidth - innerWidth,
        p.scrollWidth - p.clientWidth,
        sh ? sh.scrollWidth - sh.clientWidth : 0,
      );
    });
  const hold = async () => {
    await ev(() =>
      document
        .querySelector(".sheet.show [data-hold]")
        .dispatchEvent(new PointerEvent("pointerdown", { bubbles: true })),
    );
    await wait(2000);
  };
  // A hash-only goto is a same-document navigation: load about:blank first for a real app start.
  const boot = async () => {
    await page.goto("about:blank");
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href);
    await wait(400);
    if (prep) await prep();
  };
  const errors = [];
  page.on("pageerror", e => errors.push(String(e)));

  await boot();
  await ev(() => FOCA.api.demo_reset());
  await wait(150);
  await ev(() => FOCA.api.terms_accept("1"));
  await ev(() => FOCA.api.project_open("contoso"));
  await wait(200);

  // ---- a finished scan from the history sheet ----
  const before = await ev(() => ({
    scans: FOCA.db.scans.map(s => s.id),
    docs: FOCA.db.docs.filter(d => d.first_scan === "contoso-s2").length,
    finds: FOCA.db.findings.filter(f => f.first_scan === "contoso-s2").length,
  }));
  ok("contoso has two scans before", before.scans.length === 2 && before.docs > 0, before);
  await go("/p/scan");
  await ev(() => FOCA.actions["scan-history"]("contoso-s2"));
  await wait(400);
  ok(
    "history sheet offers Delete scan",
    await ev(() => !!document.querySelector('.sheet.show [data-act="scan-del:contoso-s2"]')),
  );
  await page.click('.sheet.show [data-act="scan-del:contoso-s2"]');
  await wait(500);
  const sheet = await ev(() => {
    const sh = document.querySelector(".sheet.show");
    return sh
      ? {
          title: (sh.querySelector(".sheet-h, h2, h3") || {}).textContent || "",
          text: sh.textContent.replace(/\s+/g, " "),
          stats: [...sh.querySelectorAll(".scn-del-g .kvr .v")].map(x => x.textContent),
          hold: !!sh.querySelector('[data-hold="scan-del-go:contoso-s2"]'),
        }
      : null;
  });
  ok("delete sheet with hold-to-confirm", sheet && sheet.hold, sheet);
  ok(
    "delete sheet shows counts from a dry run",
    sheet && sheet.stats.length === 4 && +sheet.stats[0] === before.docs,
    sheet,
  );
  ok("delete sheet explains what stays", sheet && /другие сканы/.test(sheet.text), sheet && sheet.text);
  ok("no em dash in the sheet", sheet && !sheet.text.includes("\u2014"));
  ok("no horizontal overflow in the delete sheet", (await overflow()) <= 1, await overflow());
  await shot("sheet");
  // a short tap does nothing
  await ev(() => document.querySelector(".sheet.show [data-hold]").click());
  await wait(300);
  ok("a tap does not delete", (await ev(() => FOCA.db.scans.length)) === 2);
  await hold();
  const after = await ev(() => ({
    scans: FOCA.db.scans.map(s => s.id),
    docs: FOCA.db.docs.filter(d => d.first_scan === "contoso-s2").length,
    finds: FOCA.db.findings.filter(f => f.first_scan === "contoso-s2").length,
    sheet: !!document.querySelector(".sheet.show"),
    snack: (document.querySelector("#snack") || {}).textContent || "",
    list: (FOCA.projects.find(p => p.id === "contoso") || {}).scans,
  }));
  ok("scan removed from history", after.scans.length === 1 && after.scans[0] === "contoso-s1", after);
  ok("its documents and findings are gone", after.docs === 0 && after.finds === 0, after);
  ok("snack reports the deletion", /Скан удалён/.test(after.snack), after.snack);
  ok("project card counts the remaining scan", after.list === 1, after);
  ok(
    "scan screen history lists one scan",
    (await ev(() => document.querySelectorAll('[data-act^="scan-history:"]').length)) === 1,
  );
  await shot("after");
  for (const r of ["/p/overview", "/p/findings", "/p/docs", "/p/monitor", "/p/reports"]) {
    await go(r);
    const t = await ev(() => (FOCA.page() || document.body).textContent);
    ok(`${r} renders without the deleted scan`, !t.includes("contoso-s2") && !/undefined|NaN/.test(t), r);
  }
  ok(
    "monitor history shows one scan",
    await ev(() => FOCA.db.scans.length === 1 && FOCA.sel.scans().length === 1),
  );

  // ---- a stopped scan from the stopped card ----
  await ev(() => FOCA.api.project_open("agro"));
  await wait(200);
  const agro0 = await ev(() => FOCA.db.scans.length);
  await ev(() => FOCA.api.scan_start({ project: "agro", profile: "passive" }));
  await ev(() => FOCA.api.scan_pause());
  await ev(() => {
    FOCA.api.scan_resume();
    window.FOCA_DEMO_BACKEND._ff(14);
    FOCA.api.scan_pause();
  });
  await ev(() => FOCA.api.scan_stop("user"));
  await wait(300);
  await go("/p/scan");
  const sid = await ev(() => FOCA.db.scans.slice(-1)[0].id);
  ok(
    "stopped card offers Delete scan",
    await ev(id => !!document.querySelector(`.scn-stopc [data-act="scan-del:${id}"]`), sid),
    sid,
  );
  await shot("stopped");
  ok("no horizontal overflow on the stopped card", (await overflow()) <= 1, await overflow());
  await page.click(`.scn-stopc [data-act="scan-del:${sid}"]`);
  await wait(500);
  await hold();
  const st = await ev(
    id => ({
      gone: !FOCA.db.scans.some(s => s.id === id),
      card: !!document.querySelector(".scn-stopc"),
      docs: FOCA.db.docs.filter(d => d.first_scan === id).length,
      last: (FOCA.sel.lastScan() || {}).status || null,
    }),
    sid,
  );
  ok(
    "stopped scan deleted, nothing to resume",
    st.gone && !st.card && st.docs === 0 && st.last !== "stopped",
    st,
  );
  ok("other agro scans stay", (await ev(() => FOCA.db.scans.length)) === agro0);

  // ---- a paused running scan ----
  await ev(() => FOCA.api.scan_start({ project: "agro", profile: "passive" }));
  await ev(() => FOCA.actions["scan-pause"]());
  await wait(300);
  await go("/p/scan");
  const runId = await ev(() => FOCA.scan.scanId);
  ok(
    "paused scan offers Delete scan",
    await ev(id => !!document.querySelector(`[data-act="scan-del:${id}"]`), runId),
    runId,
  );
  await shot("paused");
  await page.click(`[data-act="scan-del:${runId}"]`);
  await wait(500);
  ok(
    "running-scan sheet says it will be stopped",
    await ev(() => /остановлен/.test(document.querySelector(".sheet.show").textContent)),
  );
  await hold();
  const pz = await ev(
    id => ({
      running: FOCA.scan.running,
      status: null,
      rec: FOCA.db.scans.some(s => s.id === id),
      stopped: FOCA.scan.stopped,
    }),
    runId,
  );
  const core = await ev(() => FOCA.api.scan_status());
  ok("paused scan cancelled and erased", !pz.running && !pz.rec && !pz.stopped && !core.running, {
    pz,
    core,
  });
  ok(
    "no resume offer after deleting the paused scan",
    !(await ev(() => !!document.querySelector(".scn-stopc"))),
  );
  ok("scans of agro back to the start", (await ev(() => FOCA.db.scans.length)) === agro0);

  // ---- reference case stays out of recent projects ----
  await ev(() => FOCA.api.project_open("contoso"));
  await go("/projects");
  await ev(() => FOCA.actions["demo-case"]());
  await wait(2600);
  const refId = await ev(() => (FOCA.projects.find(p => p.reference) || {}).id || null);
  ok("reference case imported and marked", !!refId, refId);
  await ev(id => FOCA.actions["imp-open"](id), refId);
  await wait(500);
  ok("reference case opens", (await ev(() => FOCA.db.project.id)) === refId);
  const lp = await ev(() => FOCA.api.settings_get().then(s => s.last_project));
  ok("opening it does not change the last project", lp === "contoso", lp);
  await go("/projects");
  ok(
    "reference case is not among recent projects",
    !(await ev(id => !!document.querySelector(`.pj-list [data-pj="${id}"]`), refId)),
  );
  ok(
    "recent projects still listed",
    (await ev(() => document.querySelectorAll(".pj-list .pj-card").length)) > 0,
  );
  await shot("projects");
  // opening it again finds the existing case
  await ev(() => FOCA.actions["demo-case"]());
  await wait(400);
  ok(
    "Open reference case finds the existing one",
    await ev(id => !!document.querySelector(`.sheet.show [data-act="imp-open:${id}"]`), refId),
  );
  await ev(() => FOCA.closeSheet());
  // an old last_project pointing to a reference case is not restored on start
  await ev(id => FOCA.api.settings_set({ last_project: id }), refId);
  await wait(300);
  await boot();
  await wait(300);
  const cur = await ev(() => FOCA.db.project && FOCA.db.project.id);
  ok("start does not restore a reference case", cur && cur !== refId, cur);
  ok("no page errors", errors.length === 0, errors);
  console.log(`${oks} OK, ${fails} FAIL`);
};
