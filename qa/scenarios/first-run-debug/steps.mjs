// Demo: first run → terms (button disabled until every checkbox is ticked and the text is read) → permissions → intro;
// the active launch takes one tap on "start", with no checkbox, hold or confirmation log;
// Debug: log, requests, crashes, device, export; no contract anywhere.
// qa/shoot.sh --routes /p/overview --out qa/scenarios/first-run-debug --steps $PWD/qa/scenarios/first-run-debug/steps.mjs
import fs from "fs";
export default async (page, { out, prep }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const go = async r => { await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(250); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).innerText);
  const act = async (a, arg) => { await ev(([a, arg]) => FOCA.actions[a](arg, document.querySelector(`[data-act="${a}${arg !== undefined ? ":" + arg : ""}"]`)), [a, arg]); await wait(250); };
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/first_run_debug_${n}.png` }); };
  try {
    await go("/projects"); await ev(() => FOCA.api.demo_reset()); await wait(300);
    // First run.
    await act("demo-first-run"); await wait(300);
    ok('"Первый запуск" demo → /terms', await ev(() => FOCA.current()) === "/terms");
    await go("/projects");
    ok("without consent any route opens /terms", await ev(() => FOCA.current()) === "/terms");
    ok('"Принимаю" disabled initially', await ev(() => document.querySelector("#ob-accept").disabled));
    ok("text: GPL, art. 361, telemetry, 18+", /GPL/.test(await txt()) && /361/.test(await txt()) && /телеметри/.test(await txt()) && /18/.test(await txt()));
    await shot("terms");
    for (const k of ["read", "own", "resp"]) await act("ob-check", k);
    await ev(() => document.querySelector("#ob-end").scrollIntoView()); await wait(400);
    ok("three checkboxes: still disabled", await ev(() => document.querySelector("#ob-accept").disabled));
    await act("ob-check", "age");
    ok("all checkboxes and read: enabled", await ev(() => !document.querySelector("#ob-accept").disabled));
    await act("ob-accept"); await wait(300);
    ok("after consent → /permissions", await ev(() => FOCA.current()) === "/permissions");
    ok("consent stored in backend state", (await ev(() => FOCA.api.terms_get())).accepted === true);
    ok("permissions: notifications not granted, Xiaomi section", /Не выдано/.test(await txt()) && /Автозапуск/.test(await txt()) && /Контроль активности/.test(await txt()));
    await shot("permissions");
    await act("ob-notif"); await wait(300);
    ok("notifications granted after request", await ev(() => /Выдано/.test(document.querySelector("#ob-p-notif").innerText)));
    await act("ob-next"); await wait(300);
    ok("after permissions → /welcome", await ev(() => FOCA.current()) === "/welcome");
    // Declining in the demo shows a placeholder screen.
    await act("demo-first-run"); await wait(300); await act("ob-decline"); await wait(300);
    ok('"Не принимаю" → "Условия не приняты" stub', /Условия не приняты/.test(await txt()));
    await act("ob-back-terms"); await ev(() => FOCA.api.terms_accept("1")); await wait(100);
    // Active launch.
    await go("/projects"); await ev(() => FOCA.api.project_open("contoso")); await wait(200);
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go("/new"); }); await wait(250);
    await act("la-prof", "full");
    const c = await ev(() => ({ hold: !!document.querySelector("[data-hold]"), btn: document.querySelector("#la-start").textContent, t: FOCA.page().innerText }));
    ok('"Полный" wizard: "Запустить" button, no checkbox or hold', !c.hold && /Запустить/.test(c.btn) && !/разрешение на активную проверку/.test(c.t) && !/оговор/.test(c.t), c.t.slice(0, 200));
    await act("la-start"); await wait(400);
    ok('"Полный" started with one tap: scan running, active phase', await ev(() => FOCA.scan.running && FOCA.scan.active && FOCA.current() === "/p/overview"));
    ok("no confirmation log command", await ev(() => !FOCA.api.active_acks));
    await shot("full_started");
    await ev(() => FOCA.api.scan_stop("user")); await wait(300);
    const e1 = await ev(() => FOCA.api.scan_start({ profile: "full", active: true }).then(() => "started", e => e.code));
    ok('core: "Полный" starts without extra fields', e1 === "started", e1);
    await ev(() => FOCA.api.scan_stop("user")); await wait(300);
    await go("/p/scope");
    ok('scope: no contract or "Разрешить активные проверки", has "Активная фаза"', !/оговор/.test(await txt()) && !/Разрешить активные|Разрешено активно/.test(await txt()) && /Активная фаза/.test(await txt()) ); // the demo project no longer has an authorization note; the field is optional
    await shot("scope");
    // Debug.
    await go("/settings/debug"); await wait(300);
    ok("log: lines with levels", await ev(() => document.querySelectorAll(".dbg-l").length > 5));
    await act("dbg-src", "android");
    ok("Android source filter", await ev(() => [...document.querySelectorAll(".dbg-tg")].every(e => /android/.test(e.textContent))));
    await act("dbg-src", "all");
    await act("dbg-seg", "req"); await wait(300);
    ok("requests: method/host/code/access type", await ev(() => document.querySelectorAll(".dbg-r").length > 0) && /Касание цели/.test(await txt()));
    await act("dbg-seg", "crash"); await wait(200);
    ok("crashes: crash-*.txt file", /crash-/.test(await txt()));
    await act("dbg-seg", "dev"); await wait(300);
    ok("device: model, ABI, memory", /Redmi/.test(await txt()) && /arm64/.test(await txt()) && /Память/.test(await txt()));
    await act("dbg-share"); await wait(300);
    ok("share logs: archive", await ev(() => /Журналы собраны/.test((document.querySelector("#snack, .snack") || {}).innerText || "")));
    await go("/settings/about");
    ok('"О программе" → "Условия использования"', /Условия использования/.test(await txt()));
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e).slice(0, 500)]); }
  try { fs.writeFileSync(`${out}/first_run_debug_steps.json`, JSON.stringify({ ok: log.length - fails, fail: fails, log }, null, 1)); } catch (e) {}
  console.error(log.map(l => `${l[0]} ${l[1]}${l[0] === "FAIL" ? " " + JSON.stringify(l[2] ?? "").slice(0, 400) : ""}`).join("\n"));
  console.error(`first-run-debug: ${log.length - fails} OK, ${fails} FAIL`);
};
