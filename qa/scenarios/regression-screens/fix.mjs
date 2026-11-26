// Regression evidence (findings, search, reports, data, settings, v2) plus a pass over ALL projects.
// Run: qa/shoot.sh --routes "/p/overview" --out qa/scenarios/regression-screens --steps $PWD/qa/scenarios/regression-screens/fix.mjs
export default async (page, { out, W, prep }) => {
  const res = []; const ok = (name, cond, info = "") => res.push({ name, ok: !!cond, info: cond ? "" : String(info).slice(0, 300) });
  const shot = async n => { await page.waitForTimeout(300); await page.screenshot({ path: `${out}/fix_${n}_${W}.png` }); };
  const go = async r => { await page.waitForTimeout(120); await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };
  const ev = (fn, a) => page.evaluate(fn, a);
  const click = async sel => { await page.locator(sel).first().click({ timeout: 5000 }); await page.waitForTimeout(250); };
  const txt = () => ev(() => document.querySelector(".page").innerText + " " + (document.querySelector(".sheet.show") ? document.querySelector(".sheet.show").innerText : ""));
  const reset = async () => { await ev(() => FOCA.api.demo_reset()); await page.waitForTimeout(200); };

  await go("/projects"); await reset();
  try {

  // Sticky triage panel within thumb reach, 48 px; a mutation through F.api survives a reload.
  await go("/p/finding/3");
  const foot = await ev(() => [...document.querySelectorAll(".fd-foot .btn")].map(b => { const r = b.getBoundingClientRect(); return { h: Math.round(r.height), y: Math.round(r.top), t: b.textContent.trim() }; }));
  ok("UX11: triage bar 3 buttons ≥48 px in the lower half of the screen", foot.length === 3 && foot.every(b => b.h >= 48 && b.y > 426), JSON.stringify(foot));
  await ev(() => document.querySelector(".page").scrollTop = 99999); await page.waitForTimeout(150);
  const footAfter = await ev(() => { const r = document.querySelector(".fd-foot").getBoundingClientRect(); return r.bottom <= innerHeight && r.top > innerHeight / 2; });
  ok("UX11: bar stays visible while scrolling", footAfter);
  await click('.fd-foot [data-act="fd-set:3:confirmed"]');
  await page.reload(); await page.waitForTimeout(500); await prep();
  ok("C/logic #12: finding status saved via F.api (after reload)", (await ev(() => FOCA.db.findings.find(f => f.id === 3).status)) === "confirmed");
  await shot("01_triage");

  // A secret in evidence is revealed via fingerprint.
  await go("/p/finding/4");
  await click('[data-act="fd-reveal:4"]');
  const masked = await ev(() => document.querySelector(".fd-ev .secret").classList.contains("masked"));
  const finger = await ev(() => !!document.querySelector(".sheet.show .dt-finger"));
  ok("UX17: revealing a secret asks for fingerprint, hidden until confirmed", masked && finger);
  await click('[data-act="dt-finger-ok"]');
  ok("UX17: secret revealed after confirmation", !(await ev(() => document.querySelector(".fd-ev .secret").classList.contains("masked"))));
  // Screenshots are allowed by default (sec.block_shots is opt-in), so the advice is shown; once blocked it is gone.
  ok('logic #36: with screenshots allowed (default) the "не делайте скриншоты" advice is shown', /Не делайте скриншоты/.test(await txt()));
  await ev(() => { FOCA.db.settings.sec = { ...(FOCA.db.settings.sec || {}), block_shots: true }; FOCA.render(true); });
  await page.waitForTimeout(250);
  ok('logic #36: with screenshots blocked there is no "не делайте скриншоты" advice', !/Не делайте скриншоты/.test(await txt()));
  await ev(() => { FOCA.db.settings.sec = { ...(FOCA.db.settings.sec || {}), block_shots: false }; });
  await shot("02_secret");

  // "Add to report" keeps the selection and the builder honours it.
  await click('[data-act="fd-more:4"]'); await click('[data-act="fd-to-report:4"]');
  ok("UX7: selection in settings.report.picked", JSON.stringify(await ev(() => FOCA.sel.reportPicked())) === "[4]");
  await go("/p/report-new");
  ok('UX7: builder shows "Только выбранные (1)"', /Только выбранные \(1\)/.test(await txt()));
  await click('[data-act="rp-picked"]');
  // The default is "all except false positives", so a picked unconfirmed finding is included.
  ok("UX7: with selection the report has exactly 1 finding", /1 находка/.test(await ev(() => document.querySelector(".rp-foot-s").textContent)), await ev(() => document.querySelector(".rp-foot-s").textContent));
  await click('[data-act="rp-conf"]');
  ok('UX7: with "только подтверждённые": hint that unconfirmed selected ones are excluded', /не подтверждена|не подтверждены/.test(await txt()));
  await click('[data-act="rp-conf"]');
  // The draft survives a template switch and re-entry.
  await click('[data-act="rp-d:minSev:high"]'); await click('[data-act="rp-sec:docs"]');
  await click('[data-act="rp-d:tpl:brief"]');
  const d1 = await ev(() => ({ minSev: FOCA.state.reports.d.minSev, tpl: FOCA.state.reports.d.tpl, docs: FOCA.state.reports.d.sec.docs, picked: FOCA.state.reports.d.pickedOnly }));
  ok("UX8: template change keeps filters and manual sections", d1.minSev === "high" && d1.tpl === "brief" && d1.picked === true, JSON.stringify(d1));
  await page.waitForTimeout(400); await page.reload(); await page.waitForTimeout(500); await prep();
  await go("/p/reports"); await click('[data-act="rp-new"]');
  const d2 = await ev(() => ({ minSev: FOCA.state.reports.d.minSev, tpl: FOCA.state.reports.d.tpl, picked: FOCA.state.reports.d.pickedOnly }));
  ok("UX8: re-entry and reload, same settings", d2.minSev === "high" && d2.tpl === "brief" && d2.picked === true, JSON.stringify(d2));
  await shot("03_report_new");
  // Preview from data, risk via F.sel.risk, no null/undefined.
  // The report language follows the UI language by default (RU here); these checks read the Ukrainian preview.
  await click('[data-act="rp-d:lang:UA"]');
  await click('[data-act="rp-d:tpl:full"]'); await click('[data-act="rp-picked"]'); await click('[data-act="rp-conf"]'); await click('[data-act="rp-d:minSev:all"]');
  await click('[data-act="rp-preview"]');
  const pv = await txt();
  ok("logic #32: no null/undefined/NaN in preview", !/undefined|null|NaN/.test(pv), pv.slice(0, 200));
  // Report risk (API.md, Report.result) is computed over the included findings (same rule as FOCA_RULES.riskScore), not the project risk.
  const rk = await ev(() => { const d = FOCA.state.reports.d; const list = FOCA.sel.reportFindings({ confirmed: d.confirmed, min_sev: d.minSev, picked_only: d.pickedOnly, picked: d.picked || undefined }).main; const score = FOCA.rules.riskScore(list); return { score, level: FOCA.rules.riskLevel(score), n: list.length, project: FOCA.sel.risk().score }; });
  const lvl = { high: "Високий", mid: "Середній", low: "Низький" }[rk.level];
  ok('logic #9/N13: preview risk, by report findings, level caption and "за знахідками звіту: N"', pv.includes(rk.score + "/100") && pv.includes(lvl) && pv.includes(`за знахідками звіту: ${rk.n}`), JSON.stringify(rk));
  const top = await ev(() => FOCA.sel.reportFindings({ confirmed: true, min_sev: "all" }).main.slice(0, 1).map(f => f.title)[0]);
  ok("logic #32: summary names the top findings of the selection", top && pv.includes(top), top);
  ok("logic #33: fixed ones, separate section", /Виправлено/.test(pv));
  await shot("04_preview");
  // A report preview from history uses that report's parameters.
  await go("/p/reports"); await click('[data-act="rp-open:1"]');
  const sub = await ev(() => document.querySelector("#tb-s").textContent + " | " + document.querySelector(".rp-pinfo").textContent);
  ok("UX8: preview from history, by saved opts (EN, HTML)", /v1\.html/.test(sub) && /HTML · EN/.test(sub), sub);
  // Wordlist export from E-mail selects the e-mail type.
  await go("/p/data/emails"); await click('[data-act="dt-mail-export"]'); await click('[data-act="rp-ex-fmt:dict"]');
  ok("UX9: e-mail wordlist opened from E-mail", (await ev(() => (document.querySelector('.sheet [data-act^="rp-ex-dict"].on') || {}).dataset?.act)) === "rp-ex-dict:emails");
  await ev(() => FOCA.closeSheet());
  // Login wordlist from People and from a person card.
  await go("/p/data/people"); await click('[data-act="dt-dict:people"]');
  const dictPeople = await txt();
  ok('UX3: login wordlist from "Люди" screen', /Логины людей проекта/.test(dictPeople) && (await ev(() => (document.querySelector('.sheet [data-act^="rp-ex-dict"].on') || {}).dataset?.act)) === "rp-ex-dict:users");
  await ev(() => FOCA.closeSheet());
  await go("/p/entity/person/a.bondar"); await click('[data-act="dt-dict:a.bondar"]');
  ok("UX3: login wordlist from person card", /a\.bondar[\s\S]*abondar/.test(await txt()));
  await ev(() => FOCA.closeSheet());

  // Deleted source document.
  await ev(() => FOCA.api.doc_delete([1])); await page.waitForTimeout(250);
  await go("/p/finding/4");
  ok('logic #12: finding with deleted document, "Источник удалён"', await ev(() => !!document.querySelector(".fd-gone")));
  await shot("05_source_deleted");
  await click('[data-act="fd-restore-doc:1"]');
  ok("logic #12: document restore from finding card", await ev(() => !document.querySelector(".fd-gone") && !FOCA.db.docs.find(d => d.id === 1).deleted));

  // The finding is the first breadcrumb.
  await go("/p/finding/4"); await click('.fd-srcdoc .row');
  ok("UX12: one button from document back to finding (breadcrumbs)", await ev(() => !!document.querySelector('.dt-crumbs [data-act="dt-crumb:0"]')));
  // A tag acts as a filter; deletion has its own button.
  await go("/p/finding/4"); await click('[data-act^="fd-tag-filter"]');
  ok("UX23: tag tap filters the list, tag not removed", await ev(() => FOCA.current() === "/p/findings" && !!FOCA.state.findings.f.tag && FOCA.db.findings.find(f => f.id === 4).tags.length === 2));
  await ev(() => { FOCA.state.findings.f.tag = ""; });
  // Multi-select without a long press.
  await go("/p/findings"); await click('[data-act="fd-sel-start"]');
  ok('UX19: "Выбрать несколько" header button enables selection mode', await ev(() => !!FOCA.state.findings.sel && !!document.querySelector(".fd-selbar")));
  await page.goBack(); await page.waitForTimeout(300);

  // Global search.
  await go("/p/findings"); await click("#searchpill");
  ok('UX4: search from "Находки" opens with "Находки" chip', (await ev(() => document.querySelector("#gchips .chip.on").dataset.act)) === "gchip:findings");
  await page.fill("#gq", "contoso"); await page.waitForTimeout(250);
  const onlyF = await ev(() => [...document.querySelectorAll("#gres .sec-h h2")].map(h => h.textContent));
  ok("UX4: chip filters by type", onlyF.length === 1 && onlyF[0] === "Находки", JSON.stringify(onlyF));
  await click('[data-act="gchip:emails"]');
  ok("UX4: e-mail search", (await ev(() => [...document.querySelectorAll("#gres .sec-h h2")].map(h => h.textContent))).join() === "E-mail");
  await click('[data-act="gchip:findings"]'); await page.fill("#gq", "AWS"); await page.waitForTimeout(250);
  await click("#gres .row"); await page.goBack(); await page.waitForTimeout(400);
  ok('UX4: query and filter persist after "Назад"', (await ev(() => [document.querySelector("#gq").value, document.querySelector("#gchips .chip.on").dataset.act].join("|"))) === "AWS|gchip:findings");
  await shot("06_search");

  // Overview: redraw on db events.
  await go("/p/overview");
  // The risk score saturates near 100 with many findings, so the critical counter is the visible change.
  const r0 = await ev(() => FOCA.sel.counts().findings.crit);
  await ev(() => { const f = FOCA.db.findings.find(x => x.sev === "crit" && FOCA.sel.isLive(x)); FOCA.api.finding_set_status(f.id, "false"); FOCA.emit("db", { kind: "findings" }); });
  await page.waitForTimeout(400);
  const r1 = await ev(() => FOCA.sel.counts().findings.crit);
  ok("Overview re-renders on db event without navigation", r1 === r0 - 1 && (await ev(s => document.querySelector(".page").innerText.includes(`критичных: ${s}`), r1)), `${r0}→${r1}`);

  // Excluded host, DNS from data, graph only with a node.
  await go("/p/entity/host/mail.contoso.example");
  ok('logic #3: host has "В исключениях скоупа" mark', /В исключениях скоупа/.test(await txt()));
  await go("/p/entity/host/contoso.example");
  ok("logic #29: host DNS records from data (MX/SPF/DMARC/NS)", await ev(() => { const h = FOCA.db.hosts.find(x => x.name === "contoso.example"); return h.dns.every(r => document.querySelector(".page").innerText.includes(r[1].split(",")[0])); }));
  await go("/p/entity/person/y.hrytsenko");
  ok('logic #29: "Граф связей" hidden when the node has no links', await ev(() => !document.querySelector('[data-act^="go:/p/graph"]')));
  await go("/p/entity/person/a.bondar");
  ok('logic #29: "Граф связей" present on a linked node', await ev(() => !!document.querySelector('[data-act^="go:/p/graph"]')));
  await go("/p/data/os");
  ok('logic #37: "ОС" segment from metadata', /Microsoft Windows/.test(await txt()));

  // Settings: persistence, confirmations, texts.
  await go("/settings/power"); await click('.st-tr[data-act="st-t:power.wifiOnly"] .body');
  await page.waitForTimeout(200); await page.reload(); await page.waitForTimeout(500); await prep();
  ok("UX16/logic #24: toggle by row tap survives reload", (await ev(() => FOCA.db.settings.power.wifi_only)) === false);
  // Detected steps (autostart, battery) have no manual Done: mark the first step that is checked by hand.
  await go("/settings/battery");
  const manualIdx = await ev(() => { const b = document.querySelector('[data-act^="st-bdone:"]'); return b ? +b.dataset.act.split(":")[1] : -1; });
  await click(`[data-act="st-bdone:${manualIdx}"]`);
  await page.reload(); await page.waitForTimeout(500); await prep();
  ok("Settings: UI sections (settings.ui) survive reload", manualIdx >= 0 && await ev(i => !!(FOCA.state.settings.battery.done[FOCA.state.settings.battery.oem] || {})[i], manualIdx));
  await go("/settings/network"); await click('.st-tr[data-act="st-t:net.kill"] .body');
  ok("UX16: disabling kill switch, sheet with hold, value unchanged", await ev(() => !!document.querySelector('.sheet.show [data-hold^="st-net-off:net.kill"]') && FOCA.db.settings.net.kill_switch === true));
  await shot("07_kill_confirm");
  await ev(() => FOCA.closeSheet());
  ok('logic #35: "Частный DNS" text is technically accurate', /только на системный резолвер/.test(await txt()) && /53/.test(await txt()));
  await go("/settings/security");
  ok("auto-delete: by last scan, no contract", /после последнего скана/.test(await txt()) && !/оговор/.test(await txt()));
  await go("/settings/keys"); await click('[data-act="st-key:brave"]'); await click('[data-act="st-keye"]');
  ok('UX17: "Показать ключ": via fingerprint', await ev(() => !!document.querySelector(".st-finger") && document.querySelector("#st-kv").type === "password"));
  await click('[data-act="st-finger-ok"]');
  ok("UX17: key shown after fingerprint", (await ev(() => document.querySelector("#st-kv").type)) === "text");
  await ev(() => FOCA.closeSheet());
  await ev(() => FOCA.openKeySheet("censys")); await page.waitForTimeout(300);
  ok("API: F.openKeySheet(service) opens the key sheet", await ev(() => /Censys/.test((document.querySelector(".sheet.show") || {}).innerText || "")));
  await ev(() => FOCA.closeSheet());

  // v2: plugins, AI from data.
  await go("/settings/plugin/sqli");
  ok("SQLi not blocked by contract, toggle available", !/договор/.test(await txt()) && await ev(() => !document.querySelector(".v2p-hon .toggle").disabled));
  await go("/p/ai"); await click('[data-act="v2ai-step:1"]');
  const pre = await ev(() => document.querySelector(".v2ai-pre").innerText);
  ok("v2: AI preview from data, client/secrets replaced", /\[КЛИЕНТ\]/.test(pre) && /\[СЕКРЕТ\]/.test(pre) && !/Контосо/.test(pre), pre.slice(0, 200));
  await go("/p/preflight"); await click('[data-act="v2pf-pick"]'); await click("#v2pf-ok");
  ok("I-19: pre-publication check shows what leaks", /Что утечёт/.test(await txt()) && await ev(() => document.querySelectorAll(".v2pf-file").length > 0));
  await click('[data-act="v2pf-clean:all"]');
  ok("I-19: copy cleaning", /Очищенные копии сохранены/.test(await txt()));
  await shot("08_preflight");
  await go("/p/overview"); await ev(() => FOCA.actions.menu()); await page.waitForTimeout(200); await click('[data-act="v2-tools"]');
  ok('I-19: item in "Инструменты" menu', /Проверка перед публикацией/.test(await txt()));

  // All projects: no contoso data anywhere, empty states in the empty project.
  const ROUTES = ["/p/overview", "/p/findings", "/p/data/docs", "/p/data/people", "/p/data/emails", "/p/data/hosts", "/p/data/os", "/p/data/secrets", "/p/reports", "/p/report-new", "/p/report-preview", "/p/ai", "/p/preflight", "/settings/plugins", "/settings/security", "/settings/power", "/settings/appearance", "/p/map", "/p/timeline", "/p/diff", "/p/search"];
  const projects = await ev(() => FOCA.projects.map(p => p.id));
  for (const id of projects) {
    await go("/projects"); await ev(id => FOCA.api.project_open(id), id); await page.waitForTimeout(150);
    const hosts = await ev(() => FOCA.db.hosts.map(h => h.name));
    const routes = ROUTES.concat(hosts.slice(0, 2).map(h => "/p/entity/host/" + encodeURIComponent(h)), (await ev(() => FOCA.db.findings.slice(0, 2).map(f => "/p/finding/" + f.id))));
    const bad = [];
    for (const r of routes) {
      await ev(r => { FOCA.reset(["/projects", r]); }, r); await page.waitForTimeout(120);
      if (r === "/p/search") { await page.fill("#gq", "а"); await page.waitForTimeout(120); }
      const t = await txt();
      if (id !== "contoso" && /contoso|Контосо|a\.bondar|ПТ-2026\/114/i.test(t)) bad.push(r + ": " + (t.match(/.{0,40}(contoso|Контосо|a\.bondar|ПТ-2026\/114).{0,40}/i) || [""])[0]);
      if (/undefined|NaN|\[object Object\]/.test(t)) bad.push(r + ": undefined/NaN");
    }
    ok(`All projects: ${id}, no foreign data and no undefined`, !bad.length, bad.join(" || "));
    if (id === "dnipro") {
      await ev(() => FOCA.reset(["/projects", "/p/findings"])); await page.waitForTimeout(150);
      const e1 = await ev(() => !!document.querySelector(".page > .empty"));
      await ev(() => FOCA.reset(["/projects", "/p/data/people"])); await page.waitForTimeout(150);
      const e2 = await ev(() => !!document.querySelector(".dt-segbody .empty"));
      await ev(() => FOCA.reset(["/projects", "/p/report-new"])); await page.waitForTimeout(150);
      const e3 = await ev(() => !!document.querySelector(".page > .empty"));
      ok("Empty project (dnipro): empty states of findings, data, report builder", e1 && e2 && e3, JSON.stringify([e1, e2, e3]));
      await shot("09_dnipro_findings");
    }
  }

  } catch (e) { res.push({ name: "SCENARIO ABORTED after: " + (res[res.length - 1] || {}).name, ok: false, info: e.message.split("\n")[0] }); }
  const fails = res.filter(r => !r.ok);
  console.error(JSON.stringify({ W2_fix: { pass: res.length - fails.length, fail: fails.length, fails, all: res.map(r => (r.ok ? "✓ " : "✗ ") + r.name) } }, null, 1));
};
