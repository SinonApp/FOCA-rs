// Evidence scenario for logic and the API contract.
// qa/shoot.sh --routes /projects --out qa/scenarios/regression-logic --steps $PWD/qa/scenarios/regression-logic/fix.mjs [--sec A,B,…]
// Sections (each < 180 s): A: "standard"/active phase launch, engagement parameters; B: resume/restart, reload;
// C: new project wizard (draft, project created only on launch); D: report, preflight, project properties, plugins, AI.
import fs from "fs";
const secArg = (() => { const i = process.argv.indexOf("--sec"); return i > 0 ? process.argv[i + 1].split(",") : ["A", "B", "C", "D"]; })();
export default async (page, { out, prep }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const sfx = await page.evaluate(() => `${innerWidth}_fs${getComputedStyle(document.documentElement).getPropertyValue("--fs").trim() || 1}_${document.documentElement.dataset.theme}`);
  const shot = async n => { await page.waitForTimeout(350); await page.screenshot({ path: `${out}/fix_${n}_${sfx}.png` }); };
  const go = async r => { await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(250); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).innerText);
  const open = id => ev(i => FOCA.api.project_open(i), id);
  try {
    if (secArg.includes("A")) {
      // Light "standard" launch without hold or legal warning; a target typed in the wizard does not enter the scope.
      await go("/projects"); await open("contoso");
      await ev(() => { FOCA.go("/new"); }); await wait(250);
      await ev(() => FOCA.actions["la-prof"]("std")); await wait(150);
      const sc0 = await ev(() => FOCA.db.scope.targets.length);
      await ev(() => { const ta = FOCA.page().querySelector("#la-in"); ta.value = "evil-competitor.com\n"; ta.dispatchEvent(new Event("input")); }); await wait(200);
      ok("N7: wizard target not written to scope", await ev(n => FOCA.db.scope.targets.length === n && !FOCA.sel.scope.allows("evil-competitor.com"), sc0) && /только для этого скана/.test(await txt()));
      // "Standard" takes one tap, without a confirmation screen; an out-of-scope target does not reach the scan.
      await ev(() => FOCA.actions["la-start"]()); await wait(400);
      const st1 = await ev(() => ({ path: FOCA.current(), run: FOCA.scan.running, prof: FOCA.scan.profile, targets: FOCA.scan.targets, snack: document.querySelector("#snack").textContent }));
      ok('"Стандартный" started with one tap; out-of-scope target not scanned', st1.path !== "/confirm-active" && st1.run && st1.prof === "Стандартный" && !st1.targets.includes("evil-competitor.com") && /пропущено вне скоупа: 1/.test(st1.snack), st1);
      await shot("A1_std_started");
      await ev(() => FOCA.api.scan_stop("user")); await wait(300);
      // Resuming after a scope change happens immediately with the current targets (the excluded one is filtered out).
      await ev(() => FOCA.api.scope_set({ excl: FOCA.db.scope.excl.concat("contoso.example") })); await wait(200);
      await ev(() => FOCA.go("/p/scan-stopped")); await wait(300);
      await ev(() => FOCA.actions["scan-continue"]()); await wait(400);
      const st2 = await ev(() => ({ path: FOCA.current(), run: FOCA.scan.running, resumed: FOCA.scan.resumed, t: FOCA.scan.targets }));
      ok("N6/C2: resume, immediate, with current scope (without the excluded target), same record", st2.path !== "/confirm-active" && st2.run && st2.resumed && !st2.t.includes("contoso.example"), st2);
      await ev(() => FOCA.api.scan_stop("user")); await ev(() => FOCA.api.scope_set({ excl: FOCA.db.scope.excl.filter(x => x !== "contoso.example") })); await wait(200);
      // "Full" takes one tap: no checkbox, no hold, no legal article before the start.
      await ev(() => { FOCA.state.launch.leave = true; FOCA.go("/new"); }); await wait(200);
      await ev(() => FOCA.actions["la-prof"]("full")); await wait(150);
      const c3 = await ev(() => { const pg = FOCA.page(); return { hold: !!pg.querySelector("[data-hold]"), btn: (pg.querySelector("#la-start") || {}).textContent, law: /361/.test(pg.innerText), ack: /разрешение на активную/.test(pg.innerText) }; });
      ok('"Полный" wizard has no checkbox, hold or criminal code article; "Запустить" button', !c3.hold && !c3.law && !c3.ack && /Запустить/.test(c3.btn), c3);
      await ev(() => FOCA.actions["la-start"]()); await wait(400);
      const c4 = await ev(() => ({ run: FOCA.scan.running, active: FOCA.scan.active, path: FOCA.current() }));
      ok('"Полный" started with one tap (active phase)', c4.run && c4.active && c4.path === "/p/overview", c4);
      await shot("A3_full_started");
      await ev(() => FOCA.api.scan_stop("user")); await wait(300);
      ok("no confirmation routes", await ev(() => !FOCA.routes.some(r => r.pattern === "/confirm-active" || r.pattern === "/confirm-scope")));
      // medlab (active checks were disabled in 0.2.x): "full" also starts right away.
      await go("/projects"); await open("medlab");
      await ev(() => { FOCA.state.launch.leave = true; FOCA.go("/new"); }); await wait(200);
      await ev(() => FOCA.actions["la-prof"]("full")); await ev(() => FOCA.actions["la-start"]()); await wait(400);
      const c5 = await ev(() => ({ run: FOCA.scan.running, active: FOCA.scan.active, t: FOCA.page().innerText }));
      ok('medlab: "Полный" starts, no "договор"', c5.run && c5.active && !/оговор/.test(c5.t), c5.t.slice(0, 200));
      await ev(() => FOCA.api.scan_stop("user")); await wait(300);
      // Engagement parameters: an authorization note; there is no active checks toggle.
      await go("/projects"); await open("dnipro");
      await ev(() => FOCA.go("/p/scope")); await wait(200); await ev(() => FOCA.actions["la-params"]()); await wait(400);
      const sh0 = await ev(() => ({ num: !!document.getElementById("ct-num"), from: !!document.getElementById("ct-from"), basis: !!document.getElementById("ct-basis"), t: document.querySelector(".sheet.show").innerText }));
      ok('parameters have no contract number/term or "Разрешить активные проверки", have "Заметка о разрешении"', !sh0.num && !sh0.from && sh0.basis && !/Разрешить активные проверки/.test(sh0.t), sh0);
      await ev(() => { document.getElementById("ct-basis").value = "Письмо владельца от 18.11.2026"; });
      await ev(() => FOCA.actions["la-params-save"]()); await wait(300);
      ok("authorization note saved in scope", await ev(() => FOCA.db.scope.basis === "Письмо владельца от 18.11.2026" && /Заметка о разрешении/.test(FOCA.page().innerText)));
      await shot("A6_params");
    }
    if (secArg.includes("B")) {
      // Rescan, triage during the scan, page reload during the scan.
      await go("/projects"); await open("contoso");
      const before = await ev(() => { const C = FOCA.sel.counts(); return [C.docs.analyzed, C.people.total, C.software.total, C.secrets]; });
      // Document 7 is deleted during the scan; per API.md doc_delete, it and its secrets leave the counters.
      const d7 = await ev(() => { const d = FOCA.db.docs.find(x => x.id === 7); return { an: d && !d.deleted && ((d.status_code || d.status) === "analyzed") ? 1 : 0, sec: FOCA.db.secrets.filter(s => s.doc === 7).length }; });
      const n0 = await ev(() => FOCA.db.scans.length), s0 = await ev(() => FOCA.db.scans.filter(s => s.status === "stopped").length);
      await ev(() => FOCA.actions["scan-start"]({ profile: "passive" })); await ev(() => FOCA.scanDemo.ff(17));
      await ev(() => FOCA.api.finding_set_status(5, "confirmed")); await ev(() => FOCA.api.doc_delete([7]));
      await ev(() => FOCA.scanDemo.ff(3)); await wait(200);
      await page.reload(); await wait(400); await prep(); await wait(200);
      const r = await ev(() => { const l = FOCA.sel.lastScan(); const C = FOCA.sel.counts(); return { st: l.status, reason: l.reason, prog: l.progress, an: C.docs.analyzed, ppl: C.people.total, sw: C.software.total, sec: C.secrets, f5: FOCA.db.findings.find(f => f.id === 5).status, d7: FOCA.db.docs.find(d => d.id === 7).deleted, run: FOCA.scan.running }; });
      ok('N3: reload during scan → "прерван" (restart) record with progress', r.st === "stopped" && r.reason === "restart" && r.prog > 0 && !r.run, r);
      ok("N1: data intact after reload (triaged, people, software)", r.an === before[0] - d7.an && r.ppl === before[1] && r.sw <= before[2] && r.sec === before[3] - d7.sec, { before, d7, r });
      ok("N2: triage and deletion done during the scan are kept", r.f5 === "confirmed" && r.d7 === true, r);
      await ev(() => FOCA.go("/p/scan-stopped")); await wait(300);
      const t = await txt();
      ok('N11: "Что успели": gain for this scan; reason "Приложение перезапустилось"', /за этот скан/.test(t) && /перезапустилось/.test(t) && /Новых документов/.test(t), t.slice(0, 160));
      await shot("B1_stopped_restart");
      await ev(() => FOCA.actions["scan-continue"]()); await wait(300); await ev(() => FOCA.scanDemo.ff(60)); await wait(300);
      const r2 = await ev(() => ({ n: FOCA.db.scans.length, last: FOCA.sel.lastScan().status, stopped: FOCA.db.scans.filter(s => s.status === "stopped").length, an: FOCA.sel.counts().docs.analyzed, f5: FOCA.db.findings.find(f => f.id === 5).status }));
      ok("N3/C4: passive resume, immediate, same record becomes done, data intact", r2.last === "done" && r2.stopped === s0 && r2.n === n0 + 1 && r2.f5 === "confirmed", r2);
      // The project card updates right after triage.
      await ev(() => FOCA.api.finding_set_status(3, "false")); await ev(() => FOCA.go("/projects")); await wait(300);
      const card = await ev(() => ({ card: document.querySelector('[data-pj="contoso"] .pj-meta').innerText, n: FOCA.sel.counts().findings.open }));
      ok('N8: card on /projects recomputed after "Ложная"', card.card.includes(String(card.n)), card);
      await shot("B2_projects_card");
      // In the data the mail.* host is excluded, and so is its IP.
      ok("N4: F.sel.scope.check(excluded host IP): in exclusions", await ev(() => FOCA.sel.scope.check("203.0.113.20").code === "excluded"));
    }
    if (secArg.includes("C")) {
      // New project wizard: the project is created only on launch; Back keeps the draft.
      await go("/projects");
      await ev(() => { document.querySelector("#pj-q").value = "acme.ua, 10.1.1.0/24"; document.querySelector("#pj-new").dispatchEvent(new Event("submit", { cancelable: true })); }); await wait(300);
      await ev(() => { const i = FOCA.page().querySelector("#la-pclient"); i.value = "ACME"; i.dispatchEvent(new Event("input")); });
      await ev(() => FOCA.actions["la-prof"]("std")); await wait(200);
      const p1 = await ev(() => ({ path: FOCA.current(), created: FOCA.projects.some(p => p.name === "acme.ua"), btn: (FOCA.page().querySelector("#la-start") || {}).textContent }));
      ok('UX N5: project created only on start; "Создать проект и запустить" button', p1.path === "/new" && !p1.created && /Создать проект и запустить/.test(p1.btn), p1);
      await shot("C1_new_ready");
      await ev(() => FOCA.back()); await wait(400);
      const p2 = await ev(() => ({ path: FOCA.current(), sheet: !!document.querySelector(".sheet.show"), t: (document.querySelector(".sheet.show") || {}).innerText || "" }));
      ok('UX N4: "Назад" from wizard with data: "Выйти из мастера?" sheet', p2.path === "/new" && p2.sheet && /Выйти и сохранить черновик/.test(p2.t), p2);
      await shot("C2_leave_sheet");
      await ev(() => FOCA.actions["la-leave-keep"]()); await wait(400);
      const p3 = await ev(() => ({ path: FOCA.current(), draft: !!document.querySelector(".pj-draft"), created: FOCA.projects.some(p => p.name === "acme.ua") }));
      ok("UX N4/N5: draft saved and visible on /projects, no orphan empty project", p3.path === "/projects" && p3.draft && !p3.created, p3);
      await shot("C3_projects_draft");
      await ev(() => FOCA.actions["pj-draft"]()); await wait(300);
      const p4 = await ev(() => ({ t: FOCA.state.launch.targets.map(t => t.v), c: FOCA.state.launch.pclient }));
      ok('UX N4: "Продолжить черновик" restores targets and client', p4.t.join() === "acme.ua,10.1.1.0/24" && p4.c === "ACME", p4);
      await ev(() => FOCA.actions["la-prof"]("passive")); await ev(() => FOCA.actions["la-start"]()); await wait(500);
      const p5 = await ev(() => ({ created: FOCA.projects.some(p => p.name === "acme.ua"), run: FOCA.scan.running, proj: FOCA.scan.project, draft: !!((FOCA.db.settings.ui || {}).new_draft) }));
      ok("UX N5: project created on actual start; draft deleted", p5.created && p5.run && !p5.draft, p5);
      await ev(() => FOCA.api.scan_stop("user"));
    }
    if (secArg.includes("D")) {
      // Report: snapshot and risk over the included findings; plural forms.
      await go("/projects"); await open("contoso");
      const rep = await ev(() => FOCA.api.report_build({ tpl: "Полный отчёт пентеста", tpl_id: "full", fmt: "pdf", lang: "RU", min_sev: "crit", confirmed: false, sections: { summary: true, findings: true, fixed: false } }).then(r => ({ id: r.id, risk: r.result.risk, total: r.result.total, size: r.size })));
      await ev(() => FOCA.api.finding_set_status(4, "false"));
      await ev(id => { FOCA.state.reports.prevOf = FOCA.db.reports.find(r => r.id === id); FOCA.go("/p/report-preview"); }, rep.id); await wait(400);
      const pv = await txt();
      ok("N12/N13: preview from history, snapshot (risk by included findings), triage after build has no effect", pv.includes(String(rep.risk)) && /по находкам отчёта: \d+/.test(pv) && new RegExp(`выявлено ${rep.total} ${(n => n % 10 === 1 && n % 100 !== 11 ? "находка" : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14) ? "находки" : "находок")(rep.total)}(?![а-яё])`).test(pv), { rep, s: pv.slice(Math.max(0, pv.indexOf("1. ") - 20), pv.indexOf("1. ") + 400) });
      await shot("D1_report_snapshot");
      await ev(() => FOCA.api.finding_set_status(4, "new"));
      // Preflight: "partially cleaned" when a secret is in the text; reset with undo.
      await ev(() => { FOCA.state.v2.pf = { step: 1, files: [1, 2, 3], cleaned: [] }; FOCA.go("/p/preflight"); }); await wait(300);
      await ev(() => FOCA.actions["v2pf-clean"]("all")); await wait(400);
      const pf = await ev(() => { const c = [...FOCA.page().querySelectorAll(".v2pf-file")].map(x => ({ n: x.querySelector(".v2pf-fn").textContent, p: x.querySelector(".v2pf-fh .pill").textContent })); return { c, cleaned: FOCA.db.docs.find(d => d.id === 1).cleaned, t: FOCA.page().innerText }; });
      ok('UX N9: file with a secret in text, "Очищен частично" and "правьте документ", not green', /частично/.test(pf.c.find(x => /Договір/.test(x.n)).p) && /в тексте остался секрет/.test(pf.t) && !!pf.cleaned, pf.c);
      await shot("D2_preflight");
      await ev(() => FOCA.actions["v2pf-reset"]()); await wait(300);
      const sn = await ev(() => document.querySelector("#snack") ? document.querySelector("#snack").innerText : document.body.innerText.match(/Проверка сброшена.{0,20}/)?.[0]);
      ok("UX N10: verification reset, snackbar with undo", /Проверка сброшена/.test(sn || "") && /Отменить/.test(sn || ""), sn);
      // Project properties: alternative domains and notes via project_update/scope_set.
      await go("/projects");
      await ev(() => FOCA.projectProps("contoso")); await wait(400);
      await ev(() => { document.getElementById("pp-alt").value = "contoso.com.ua"; document.getElementById("pp-notes").value = "Связь: только через ІТ-директора"; });
      await shot("D3_props");
      await ev(() => FOCA.actions["pj-props-save"]("contoso")); await wait(400);
      const pp = await ev(() => ({ notes: FOCA.db.project.notes, alt: FOCA.db.scope.targets.some(t => t.v === "contoso.com.ua" && t.type === "domain" && !t.active) }));
      ok("F-1: notes and alternative domain saved (project_update + scope target)", /ІТ-директора/.test(pp.notes) && pp.alt, pp);
      await ev(() => FOCA.go("/p/scope")); await wait(300);
      ok('F-1: "Скоуп" shows "Альтернативный домен" and notes', /Альтернативный домен/.test(await txt()) && /ІТ-директора/.test(await txt()));
      // Plugins: Git/IIS are flagged as contacting the target like active ones, state survives a reload; HIBP needs a key.
      await ev(() => FOCA.go("/settings/plugin/git")); await wait(300);
      ok('N14: Git/SVN, active module ("Требует подтверждённого активного режима")', /Требует подтверждённого активного режима/.test(await txt()));
      await ev(() => FOCA.go("/settings/plugins")); await wait(200);
      await ev(() => FOCA.actions["v2p-on"]("recon", document.querySelector('[data-act="v2p-on:recon"]'))); await wait(200);
      await page.reload(); await wait(400); await prep(); await ev(() => FOCA.go("/settings/plugins")); await wait(300);
      const pl = await ev(() => ({ recon: document.querySelector('[data-act="v2p-on:recon"]').classList.contains("on"), hibp: document.querySelector('[data-act="v2p-on:hibp"]').classList.contains("on") }));
      ok("N15/N14: plugin disable survived reload; HIBP enabled by key", !pl.recon && pl.hibp, pl);
      await shot("D4_plugins");
      // AI summary: preview from the core, secrets stripped.
      await ev(() => FOCA.go("/p/ai")); await wait(200); await ev(() => FOCA.actions["v2ai-step"](1)); await wait(400);
      const ai = await ev(() => ({ t: FOCA.page().innerText, marks: FOCA.page().querySelectorAll("mark.v2ai-r").length }));
      ok("C9/C10: AI preview (ai_preview): secrets replaced with [SECRET], no plain values", ai.marks > 0 && /\[SECRET\]/.test(ai.t) && !/Kont0so|wJx9Fq2/.test(ai.t), ai.marks);
      await shot("D5_ai_preview");
      // Secrets are masked in the snapshot; revealing goes through secret_reveal after confirmation.
      const sec = await ev(() => ({ raw: JSON.stringify(FOCA.db.raw.secrets), v: FOCA.db.secrets[0].value }));
      ok("C10: secrets masked in snapshot", !/Kont0so#2024/.test(sec.raw) && /•/.test(sec.v), sec.v);
    }
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e).slice(0, 500)]); }
  const res = { sec: secArg, sfx, ok: log.length - fails, fail: fails, log };
  try { fs.writeFileSync(`${out}/fix_${secArg.join("")}_${sfx}.json`, JSON.stringify(res, null, 1)); } catch (e) {}
  console.error(log.map(l => `${l[0]} ${l[1]}${l[0] === "FAIL" ? " " + JSON.stringify(l[2] ?? "").slice(0, 400) : ""}`).join("\n"));
  console.error(`regression-logic [${secArg}]: ${log.length - fails} OK, ${fails} FAIL`);
};
