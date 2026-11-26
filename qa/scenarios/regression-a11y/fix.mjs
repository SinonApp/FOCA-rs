// Usability and accessibility regression evidence: Back after deep links, snackbar placement, compact panels, fingerprint session, tap targets.
// Run: qa/shoot.sh --routes /p/overview --out qa/scenarios/regression-a11y --w 360 --fs 2 --steps $PWD/qa/scenarios/regression-a11y/fix.mjs
export default async (page, { out, W, prep }) => {
  const res = []; const ok = (name, cond, info = "") => res.push({ name, ok: !!cond, info: cond ? "" : JSON.stringify(info).slice(0, 300) });
  const wait = ms => page.waitForTimeout(ms);
  const ev = (f, a) => page.evaluate(f, a);
  const go = async r => { await wait(100); await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await wait(250); await prep(); await wait(300); };
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/fix_${n}_${W}.png` }); };
  const click = async s => { try { await page.locator(s).filter({ visible: true }).first().click({ timeout: 3000 }); } catch (e) { ok("click " + s, false, e.message.split("\n")[0]); } await wait(350); };
  const reset = async st => { await ev(s => FOCA.reset(s, "none"), st); await wait(350); };
  const fsc = await ev(() => getComputedStyle(document.documentElement).getPropertyValue("--fs").trim());

  // System Back after a deep link leads to the parent.
  const PARENT = { "/p/scan": "/p/overview", "/p/scan-stopped/vpn": "/p/overview", "/new": "/p/overview", "/p/finding/4": "/p/overview", "/settings/keys": "/settings", "/p/preflight": "/p/overview", "/p/scope": "/p/overview", "/p/overview": "/projects" };
  for (const [r, up] of Object.entries(PARENT)) {
    await go(r);
    const st = await ev(() => history.state);
    let after; try { await ev(() => history.back()); await wait(500); after = await ev(() => FOCA.current()); } catch (e) { after = "LEFT"; }
    ok(`N1: ${r}, trap set, "Назад" → ${up}`, st && st.trap && after === up, { st, after });
  }
  // Chain to the root: card → overview → projects → exit (no trap at the root, Back does not loop).
  await go("/p/finding/4");
  const chain = [];
  for (let k = 0; k < 3; k++) { try { await ev(() => history.back()); await wait(450); chain.push(page.url().includes("index.html") ? await ev(() => FOCA.current() + (history.state && history.state.trap ? "+trap" : "")) : "LEFT"); } catch (e) { chain.push("LEFT"); break; } }
  ok('N1: "Назад" chain card → Overview → Projects → app exit', chain[0] === "/p/overview+trap" && chain[1] === "/projects" && chain[2] === "LEFT", chain);
  await go("/projects");
  ok('N1: no trap at /projects root (system "Назад" closes the app)', (await ev(() => history.state)) === null, await ev(() => history.state));

  // Snackbar above the sticky bottom / FAB / mini panel.
  await go("/p/overview");
  await reset(["/projects", "/p/overview", "/p/findings", "/p/finding/3"]);
  const okBtn = await ev(() => { const b = document.querySelector('.fd-foot [data-act$=":confirmed"]'); const q = b.getBoundingClientRect(); return { l: q.left, t: q.top, r: q.right, b: q.bottom }; });
  await click('.fd-foot [data-act$=":confirmed"]'); await wait(400);
  const cov = await ev(() => { const sn = document.querySelector("#snack.show"); if (!sn) return { snack: false }; const s = sn.getBoundingClientRect();
    const hits = [...document.querySelectorAll(".fd-foot .btn")].map(b => { const q = b.getBoundingClientRect(); const e = document.elementFromPoint(q.left + q.width / 2, q.top + q.height / 2); return !!(e && e.closest("#snack")); });
    const a = sn.querySelector(".sn-a").getBoundingClientRect(); return { snack: true, hits, snBottom: s.bottom, footTop: document.querySelector(".fd-foot").getBoundingClientRect().top, a: { x: a.left + a.width / 2, y: a.top + a.height / 2 } }; });
  ok('N3: after "Подтвердить" the snackbar does not cover triage buttons', cov.snack && cov.hits.every(h => !h) && cov.snBottom <= cov.footTop + 1, cov);
  ok('N3: "Отменить" not where the just-tapped button was', cov.a && !(cov.a.x >= okBtn.l && cov.a.x <= okBtn.r && cov.a.y >= okBtn.t && cov.a.y <= okBtn.b), { a: cov.a, okBtn });
  await shot("n3_finding_snack");
  // Shared mechanism: any screen with a sticky bottom, FAB, mini panel and selection bar.
  await ev(async () => { await FOCA.actions["scan-start"]({ profile: "passive" }); }); await wait(300);
  await ev(() => document.querySelector("#mi-pp")?.click()); await wait(300);
  for (const [r, st] of [["/new", ["/projects", "/p/overview", "/new"]], ["/p/report-new", ["/projects", "/p/overview", "/p/reports", "/p/report-new"]], ["/p/scan", ["/projects", "/p/overview", "/p/scan"]], ["/p/findings", ["/projects", "/p/overview", "/p/findings"]]]) {
    await reset(st);
    const c = await ev(() => new Promise(res => { FOCA.snack("Проверка снекбара", { action: () => {} }); setTimeout(() => { const bad = [...document.querySelectorAll(".page .foot .btn, .page .foot [data-act], #fab.show, #mini.show #mi-pp, #mini.show, #searchpill.show, #nav.show button")].filter(b => { const q = b.getBoundingClientRect(); if (!q.width) return false; const e = document.elementFromPoint(q.left + q.width / 2, q.top + q.height / 2); return e && e.closest("#snack"); }).map(b => (b.textContent.trim() || b.id).slice(0, 20)); document.querySelector("#snack").classList.remove("show"); res(bad); }, 400); }));
    ok(`N3: ${r}, snackbar covers nothing`, !c.length, c);
  }
  // Document selection bar.
  await reset(["/projects", "/p/overview", "/p/data/docs"]);
  const selBtn = await ev(() => !!document.querySelector('#tb-acts [data-act="dd-sel-start"]'));
  ok('#19: "Документы" header has "Выбрать несколько"', selBtn);
  await click('#tb-acts [data-act="dd-sel-start"]');
  const selOn = await ev(() => ({ ctx: !!document.querySelector(".dt-ctx"), bar: !!document.querySelector(".dt-selbar") }));
  ok("#19: button enables selection mode (contextual and bottom bars)", selOn.ctx && selOn.bar, selOn);
  const c2 = await ev(() => new Promise(res => { FOCA.snack("Проверка", { action: () => {} }); setTimeout(() => { const s = document.querySelector("#snack").getBoundingClientRect(), b = document.querySelector(".selbar").getBoundingClientRect(); document.querySelector("#snack").classList.remove("show"); res({ s: s.bottom, b: b.top }); }, 400); }));
  ok("N3: snackbar above the selection bar", c2.s <= c2.b + 1, c2);
  await ev(() => history.back()); await wait(400);
  ok('#19: system "Назад" exits selection', await ev(() => !document.querySelector(".dt-ctx") && FOCA.current() === "/p/data/docs"));
  // With a sheet open, the snackbar sits above its footer.
  await reset(["/projects", "/p/overview", "/p/findings"]);
  await click('#tb-acts [data-act="fd-filters"]');
  const c3 = await ev(() => new Promise(res => { FOCA.snack("Проверка", {}); setTimeout(() => { const s = document.querySelector("#snack").getBoundingClientRect(), f = document.querySelector(".sheet.show .sh-f").getBoundingClientRect(); res({ s: s.bottom, f: f.top }); }, 400); }));
  ok("N3: with a sheet open the snackbar is above its buttons", c3.s <= c3.f + 1, c3);
  await ev(() => FOCA.closeSheet()); await wait(300);

  // Finding card: compact bottom panels.
  await reset(["/projects", "/p/overview", "/p/findings", "/p/finding/1"]);
  const n8 = await ev(() => { const H = innerHeight; const tb = document.querySelector(".topbar").getBoundingClientRect().bottom; const foot = document.querySelector(".fd-foot").getBoundingClientRect();
    const rows = [...document.querySelectorAll(".fd-foot .btn")].map(b => Math.round(b.getBoundingClientRect().top)); const nav = document.querySelector("#nav").getBoundingClientRect();
    return { H, content: Math.round(foot.top - tb), pct: Math.round((foot.top - tb) / H * 100), oneRow: new Set(rows).size === 1, footH: Math.round(foot.height), mini: getComputedStyle(document.querySelector("#mini")).display, navH: Math.round(nav.height) }; });
  ok(`N8: content area ≥ 60 % of height (fs ${fsc}, scan paused)`, n8.pct >= 60, n8);
  ok('N8: "Ложная / Подтвердить / →" on one line, mini-panel hidden on the card', n8.oneRow && n8.mini === "none", n8);
  // A snackbar shown while a sheet was open does not stay above the sticky bottom after it closes and the user navigates.
  const stale = await ev(() => { const sn = document.querySelector("#snack"); return { show: sn.classList.contains("show"), covered: [...document.querySelectorAll(".fd-foot .btn")].some(b => { const q = b.getBoundingClientRect(); const e = document.elementFromPoint(q.left + q.width / 2, q.top + q.height / 2); return e && e.closest("#snack"); }) }; });
  ok("N3: snackbar recomputes position after sheet close and navigation", !stale.covered, stale);
  await shot("n8_finding");

  // Multi-select from a card adds no extra screen to the stack.
  await click('#tb-acts [aria-label="Ещё"]'); await click('.sheet.show [data-act^="fd-sel-many"]');
  const st12 = await ev(() => ({ stack: FOCA.stack(), sel: !!document.querySelector(".fd-ctx") }));
  ok("N12: from the card, back to the list, card not in the stack", st12.sel && st12.stack.join(">") === "/projects>/p/overview>/p/findings", st12);
  await ev(() => history.back()); await wait(350); await ev(() => history.back()); await wait(400);
  ok('N12: "Назад" exits selection, next "Назад" goes to Overview', (await ev(() => FOCA.current())) === "/p/overview", await ev(() => FOCA.stack()));
  await reset(["/projects", "/p/overview", "/p/finding/4"]); // card not opened from the list
  await click('#tb-acts [aria-label="Ещё"]'); await click('.sheet.show [data-act^="fd-sel-many"]');
  ok("N12: card not opened from the list, replaced by the list", (await ev(() => FOCA.stack().join(">"))) === "/projects>/p/overview>/p/findings", await ev(() => FOCA.stack()));
  await ev(() => history.back()); await wait(300);

  // Fingerprint session.
  await go("/p/data/secrets");
  ok("N11: default trust window is 2 min", (await ev(() => FOCA.bioMinutes())) === 2);
  await click('[data-act="dt-sec-show:1"]');
  ok("N11: first reveal, fingerprint prompt", await ev(() => !!document.querySelector(".sheet.show .dt-finger")));
  await click('[data-act="dt-finger-ok"]');
  const ind = await ev(() => ({ show: document.querySelector("#bioind").classList.contains("show"), t: document.querySelector("#bi-t").textContent, open: FOCA.bioOpen() }));
  ok('N11: indicator "Секреты открыты · 2:00 · Закрыть"', ind.show && /Секреты открыты · [12]:\d\d/.test(ind.t) && ind.open, ind);
  await shot("n11_indicator");
  await click('[data-act="dt-sec-show:2"]');
  ok("N11: second secret, no repeated fingerprint", await ev(() => !document.querySelector(".sheet.show") && document.querySelectorAll(".dt-sec .secret:not(.masked)").length === 2));
  await click('[data-act="dt-sec-copy:3"]');
  ok("N11: copying an unrevealed one, no fingerprint", await ev(() => !document.querySelector(".sheet.show") && /скопирован/.test(document.querySelector("#snack").textContent)));
  await reset(["/projects", "/p/overview", "/p/finding/4"]);
  await click('[data-act="fd-reveal:4"]');
  ok("N11: evidence in a finding, same mechanism, no fingerprint", await ev(() => !document.querySelector(".sheet.show") && !document.querySelector(".fd-ev .secret").classList.contains("masked")));
  await ev(() => FOCA.openKeySheet("shodan")); await wait(400);
  await click('.sheet.show [data-act="st-keye"]');
  ok("N11: API key, same mechanism, no fingerprint", await ev(() => !document.querySelector(".st-finger") && document.querySelector("#st-kv").type === "text"));
  await ev(() => document.querySelector("#bioind [data-act=bio-close]").click()); await wait(350); // (the sheet is modal; in practice "close" is pressed before or after it)
  ok('N11: "Закрыть" hides everything and removes the indicator', await ev(() => !FOCA.bioOpen() && !document.querySelector("#bioind").classList.contains("show") && document.querySelector("#st-kv").type === "password" && document.querySelector(".fd-ev .secret").classList.contains("masked")));
  await click('.sheet.show [data-act="st-keye"]');
  ok("N11: after closing, fingerprint again (over the key sheet)", await ev(() => !!document.querySelector(".sheet.show .st-finger")));
  await click('[data-act="st-finger-ok"]'); await ev(() => FOCA.closeSheet()); await wait(300);
  // Going to the background ends the session.
  await ev(() => { Object.defineProperty(document, "hidden", { configurable: true, get: () => true }); document.dispatchEvent(new Event("visibilitychange")); delete document.hidden; });
  ok("N11: app going to background closes the session", await ev(() => !FOCA.bioOpen() && !document.querySelector("#bioind").classList.contains("show")));
  // Locking ends the session.
  await go("/p/data/secrets"); await click('[data-act="dt-sec-show:1"]'); await click('[data-act="dt-finger-ok"]');
  await ev(() => FOCA.go("/lock")); await wait(400);
  ok("N11: lock screen closes the session", await ev(() => !FOCA.bioOpen()));
  // "Ask every time".
  await go("/settings/security");
  await click('[data-act="st-reveal:0"]');
  await go("/p/data/secrets"); await click('[data-act="dt-sec-show:1"]'); await click('[data-act="dt-finger-ok"]'); await click('[data-act="dt-sec-show:2"]');
  ok('N11: "Спрашивать каждый раз": fingerprint per secret, no indicator', await ev(() => !!document.querySelector(".sheet.show .dt-finger") && !document.querySelector("#bioind").classList.contains("show")));
  await ev(() => FOCA.closeSheet());
  await go("/settings/security"); await click('[data-act="st-reveal:2"]');
  ok("N11: window setting persists (2 min)", (await ev(() => FOCA.bioMinutes())) === 2);

  // Accurate text about background work.
  await go("/settings/battery");
  const bt = await ev(() => document.querySelector(".page").innerText);
  ok('#34: no "Android не будет останавливать" promise, persistent notification present', !/не будет останавливать/.test(bt) && /постоянным уведомлением/.test(bt), bt.slice(0, 200));
  await ev(() => FOCA.actions["st-bopen"]()); await wait(1900);
  const bt2 = await ev(() => document.querySelector(".page").innerText);
  ok("#34: after exclusion, HyperOS and firmware steps", /HyperOS/.test(bt2) && !/не будет останавливать/.test(bt2), bt2.slice(0, 260));

  // Secrets of a deleted document.
  await go("/p/data/secrets");
  const s0 = await ev(() => ({ n: document.querySelectorAll(".dt-sec").length, doc: FOCA.db.secrets[0].doc }));
  await ev(d => FOCA.api.doc_delete([d]), s0.doc); await wait(300); await ev(() => FOCA.render(true)); await wait(200);
  const s1 = await ev(d => ({ n: document.querySelectorAll(".dt-sec").length, chip: document.querySelector('.dt-seg [data-act="dt-seg:secrets"] .c')?.textContent, left: FOCA.db.secrets.filter(s => s.doc !== d).length }), s0.doc);
  ok("#12: secrets of a deleted document are neither shown nor counted in the chip", s1.n === s1.left && +s1.chip === s1.left && s1.n < s0.n, { s0, s1 });
  await ev(d => FOCA.api.doc_restore([d]), s0.doc); await wait(200);

  // Tap targets.
  await go("/p/search");
  const ch = await ev(() => [...document.querySelectorAll("#gchips .chip")].map(c => Math.round(c.getBoundingClientRect().height)));
  ok("D.2: search chips ≥ 44 px", ch.every(h => h >= 44), ch);
  await go("/p/data/emails");
  const em = await ev(() => [...document.querySelectorAll(".dt-seg .chip, .chips .chip, .btn.sm, .dt-sortb")].map(c => Math.round(c.getBoundingClientRect().height)).filter(Boolean));
  ok('D.2: "Данные" segments, e-mail filter, "Скопировать список" ≥ 44 px', em.every(h => h >= 44), em);
  await go("/p/finding/1");
  const tg = await ev(() => { const x = document.querySelector(".fd-tagx").getBoundingClientRect(); const c = document.querySelector("a.fd-cve"); const q = c.getBoundingClientRect(), a = getComputedStyle(c, "::after"); return { tagx: [Math.round(x.width), Math.round(x.height)], cve: Math.round(q.height - 2 * parseFloat(a.top)) }; });
  ok("D.2: tag close 48×48, CVE pill zone ≥ 44 px", tg.tagx[0] >= 48 && tg.tagx[1] >= 48 && tg.cve >= 44, tg);
  await go("/settings/network");
  const sg = await ev(() => [...document.querySelectorAll(".seg button")].map(b => Math.round(b.getBoundingClientRect().height)));
  ok("D.2: settings segments ≥ 44 px", sg.every(h => h >= 44), sg);

  const fail = res.filter(r => !r.ok);
  res.forEach(r => console.log((r.ok ? "OK " : "FAIL ") + r.name + (r.ok ? "" : " :: " + r.info)));
  console.log(`regression-a11y: ${res.length - fail.length} OK, ${fail.length} FAIL`);
};
