// Demo: first-time-user polish. Help lists sources in the UI language; Monitoring validates the Telegram and
// webhook fields inline (no "saved" with empty fields), reveals an empty field without a fingerprint prompt and
// shows channel errors capitalised; Debug tabs switch on deep-linked routes; request rows keep a gap between
// method and host and translate core errors. UK is the main language here, EN where wording matters.
// qa/shoot.sh --routes none --out $PWD/qa/out/ux-polish --steps $PWD/qa/scenarios/ux-polish/steps.mjs
import fs from "fs";
export default async (page, { out }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const pageText = () => ev(() => FOCA.page().textContent.replace(/\s+/g, " "));
  const snack = () => ev(() => { const s = document.querySelector(".snack"); return s && s.classList.contains("show") ? s.textContent.trim() : ""; });
  const shot = name => page.screenshot({ path: `${out}/ux_${name}.png` }).catch(() => {});
  const RU_ONLY = /[ыэъё]/i;
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    await ev(() => localStorage.setItem("foca-welcomed", "1"));
    await ev(() => FOCA.i18n.setLang("uk")); await wait(300);

    // ---- Plurals: number + noun templates pick one|few|many (uk/ru) or one|other (en) ----
    const pl = {};
    for (const l of ["uk", "ru", "en"]) {
      await ev(l => FOCA.i18n.setLang(l), l); await wait(300);
      pl[l] = await ev(() => [1, 2, 5, 21, 87663].map(n => FOCA.tp("wordlists.lines", n, { n }, "")).concat([FOCA.tp("settings.preset_applied", 2, { name: "X", threads: 2, rps: 3, timeout: 10 }, "")]));
    }
    await ev(() => FOCA.i18n.setLang("uk")); await wait(300);
    ok("plurals uk: рядок / рядки / рядків, 87 663 grouped and agreed", pl.uk.slice(0, 5).join("; ") === "1 рядок; 2 рядки; 5 рядків; 21 рядок; 87\u00a0663 рядки" && /2 потоки/.test(pl.uk[5]), pl.uk);
    ok("plurals ru: строка / строки / строк", pl.ru.slice(0, 3).join("; ") === "1 строка; 2 строки; 5 строк" && /2 потока/.test(pl.ru[5]), pl.ru);
    ok("plurals en: line / lines", pl.en.slice(0, 2).join("; ") === "1 line; 2 lines" && /87,663 lines/.test(pl.en[4]), pl.en);

    // ---- Projects: a pasted list becomes several targets ----
    await ev(() => FOCA.reset(["/projects"])); await wait(500);
    await page.click("#pj-q");
    await page.keyboard.insertText("alpha.example\nbeta.example, 192.0.2.1 - 192.0.2.9\nbad@mail.example gamma.example");
    await wait(200);
    const hint = await ev(() => document.querySelector("#pj-q-hint").textContent);
    ok("projects uk: pasted list previews 5 targets and the refused one", /5 цілей/.test(hint) && /з помилкою: 1/.test(hint), hint);
    await shot("projects_paste_uk");
    await page.keyboard.press("Enter"); await wait(600);
    const wz = await ev(() => ({ route: FOCA.current(), chips: document.querySelectorAll(".la-chips .chip, .la-chips [data-act^='la-del']").length, errs: document.querySelectorAll("[data-act^='la-fix']").length, snack: (document.querySelector(".snack.show") || {}).textContent || "" }));
    ok("wizard: four valid targets (range kept whole) and one error row", wz.route === "/new" && wz.chips === 4 && wz.errs === 1, wz);
    ok("wizard: no snackbar over the pasted list", !wz.snack.trim(), wz.snack);
    await shot("wizard_paste_uk");
    await ev(() => FOCA.reset(["/projects"])); await wait(400);
    await page.click("#pj-q"); await page.keyboard.press("Enter"); await wait(300);
    ok("projects: empty field stays and says what to enter", (await ev(() => FOCA.current())) === "/projects" && (await ev(() => document.querySelector("#pj-q-hint").classList.contains("err"))));

    // ---- Snackbar: above an open sheet's fields, short timeout, tap to dismiss ----
    await ev(() => { FOCA.sheet({ title: "QA", html: "<input class='qa-f'><input class='qa-f'><input class='qa-f'>", footer: "<button class='btn'>OK</button>" }); }); await wait(400);
    await ev(() => FOCA.snack("QA notice")); await wait(400);
    const sp = await ev(() => { const s = document.querySelector("#snack").getBoundingClientRect(), sh = document.querySelector(".sheet.show").getBoundingClientRect(); return { top: document.querySelector("#snack").classList.contains("at-top"), sb: s.bottom, sht: sh.top }; });
    ok("snackbar sits above an open sheet, not over its fields", sp.top && sp.sb <= sp.sht + 1, sp);
    await wait(3000);
    ok("plain snackbar hides after about 3 s", !(await ev(() => document.querySelector("#snack").classList.contains("show"))));
    await ev(() => FOCA.closeSheet()); await wait(300);
    await ev(() => FOCA.snack("QA tap")); await wait(300);
    await page.click("#snack .sn-t"); await wait(300);
    ok("tap on the snackbar text dismisses it", !(await ev(() => document.querySelector("#snack").classList.contains("show"))));

    // ---- First run: permissions footer, Back, last welcome slide ----
    await ev(() => FOCA.reset(["/permissions"])); await wait(700);
    const pf = await ev(() => [...document.querySelectorAll(".ob-foot .btn")].filter(b => b.offsetParent).map(b => ({ act: b.dataset.act, primary: b.classList.contains("primary"), h: Math.round(b.getBoundingClientRect().height) })));
    const footH = await ev(() => Math.round(document.querySelector(".ob-foot").getBoundingClientRect().height));
    ok("permissions: one primary action, no two buttons doing the same", pf.filter(b => b.primary).length === 1 && new Set(pf.map(b => b.act)).size === pf.length && pf.length <= 2, pf);
    ok("permissions: compact footer (under 170 px, was about 210)", footH < 170, footH);
    await shot("permissions_uk");
    const back = await ev(() => FOCA.back());
    ok("permissions: Back does not jump forward to /welcome", back === false && (await ev(() => FOCA.current())) === "/permissions", back);
    await ev(() => FOCA.reset(["/welcome"])); await wait(400);
    await ev(() => FOCA.actions["v2w-go"]("2")); await wait(500);
    const wl = await ev(() => { const st = document.querySelector(".v2w-start"); return { start: !!st && !st.hidden && st.offsetParent !== null, label: st && st.textContent.trim(), dupConsent: !!document.querySelector(".v2w-cons, [data-act='v2w-ok']") }; });
    ok("welcome last slide: a visible 'Почати' and no repeated consent checkbox", wl.start && wl.label === "Почати" && !wl.dupConsent, wl);
    await shot("welcome_last_uk");
    await ev(() => document.querySelector(".v2w-start").click()); await wait(400);
    ok("welcome: Почати opens Projects", (await ev(() => FOCA.current())) === "/projects");

    // ---- Help: sources in the UI language ----
    for (const lang of ["uk", "en"]) {
      await ev(l => FOCA.i18n.setLang(l), lang); await wait(250);
      await ev(() => FOCA.go("/help/profiles")); await wait(500);
      const t = await ev(() => [...document.querySelectorAll(".hl-src, .page h3")].map(e => e.textContent).join(" | "));
      ok(`help profiles ${lang}: source names, descriptions and groups are translated`, t.length > 200 && !RU_ONLY.test(t) && !/Архив|Поддомен/.test(t), t.slice(0, 300));
    }
    await ev(() => FOCA.i18n.setLang("uk")); await wait(250);

    // ---- Monitoring: alert channel validation ----
    await ev(() => FOCA.reset(["/p/overview", "/p/monitor"])); await wait(600);
    const tgOn = await ev(() => !!document.querySelector("#v2mo-tok"));
    if (!tgOn) { await ev(() => FOCA.actions["v2mo-t"]("tg")); await wait(400); }
    ok("monitor: Telegram fields are visible", await ev(() => !!document.querySelector("#v2mo-tok") && !!document.querySelector("#v2mo-chat")));
    // Eye on an empty token field: no fingerprint sheet.
    await ev(() => FOCA.actions["v2mo-eye"]("v2mo-tok")); await wait(300);
    const eye = await ev(() => ({ type: document.querySelector("#v2mo-tok").type, sheet: !!document.querySelector(".sheet.open, .sheet-wrap.show, .sheet.show") }));
    ok("monitor: revealing an empty token field asks for nothing", eye.type === "text" && !eye.sheet, eye);
    await ev(() => { document.querySelector("#v2mo-chat").value = ""; }); await ev(() => FOCA.actions["v2mo-save-tg"]()); await wait(400);
    const errs = await ev(() => [...document.querySelectorAll(".v2mo-f .fhint.err")].map(e => e.textContent));
    const sn = await snack();
    ok("monitor: saving empty Telegram fields shows two inline errors", errs.length === 2, errs);
    ok("monitor: no 'saved' snackbar with empty fields", !/збережено/i.test(sn), sn);
    ok("monitor: invalid field is marked aria-invalid", await ev(() => document.querySelector("#v2mo-chat").getAttribute("aria-invalid") === "true"));
    await shot("monitor_tg_errors_uk");
    await ev(() => { document.querySelector("#v2mo-tok").value = "123456789:AAH4kLm9xQ2ZtR7vW1yB3nC5dE8fG0hJ_kL"; document.querySelector("#v2mo-chat").value = "-1001987654321"; });
    await ev(() => FOCA.actions["v2mo-save-tg"]()); await wait(500);
    ok("monitor: valid Telegram fields save and clear the errors", /збережено/i.test(await snack()) && (await ev(() => document.querySelectorAll(".v2mo-f .fhint.err").length)) === 0, await snack());
    // Webhook: empty URL is refused inline.
    const whOn = await ev(() => !!document.querySelector("#v2mo-url"));
    if (!whOn) { await ev(() => FOCA.actions["v2mo-t"]("hook")); await wait(400); }
    await ev(() => FOCA.actions["v2mo-test"]("webhook")); await wait(400);
    const whErr = await ev(() => { const e = document.querySelector("#v2mo-url-err"); return e && e.textContent; });
    ok("monitor: webhook test without a URL points at the field", !!whErr, { whErr, snack: await snack() });
    ok("monitor: channel name is capitalised in the hint", /Webhook/.test(await snack()), await snack());

    // ---- Debug: tabs on a deep-linked route ----
    await ev(() => FOCA.reset(["/settings", "/settings/debug/req"])); await wait(600);
    const seg0 = await ev(() => { const b = document.querySelector('[data-act^="dbg-seg:"].on, [data-act^="dbg-seg:"][aria-checked="true"], [data-act^="dbg-seg:"][aria-selected="true"]'); return b && b.getAttribute("data-act"); });
    await ev(() => FOCA.actions["dbg-seg"]("log")); await wait(500);
    const seg1 = await ev(() => { const b = document.querySelector('[data-act^="dbg-seg:"].on, [data-act^="dbg-seg:"][aria-checked="true"], [data-act^="dbg-seg:"][aria-selected="true"]'); return b && b.getAttribute("data-act"); });
    ok("debug: deep link opens Requests, a tab tap switches to Log", seg0 === "dbg-seg:req" && seg1 === "dbg-seg:log", { seg0, seg1 });
    await ev(() => FOCA.actions["dbg-seg"]("req")); await wait(500);
    const row = await ev(() => { const r = document.querySelector(".dbg-rt"); return r && r.textContent; });
    ok("debug: method and host are separated", !row || /^[A-Z]+\s+\S/.test(row.trim()), row);
    const reqText = await ev(() => [...document.querySelectorAll(".dbg-meta")].map(e => e.textContent).join(" | "));
    ok("debug uk: request errors are not Russian", !RU_ONLY.test(reqText) && !/скоупа/.test(reqText), reqText.slice(0, 300));
  } catch (e) { fails++; log.push(["FAIL", "exception", String((e && e.stack) || e).slice(0, 500)]); }
  await ev(() => FOCA.i18n.setLang("ru")).catch(() => {});
  fs.writeFileSync(`${out}/ux_polish_steps.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] ?? "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
