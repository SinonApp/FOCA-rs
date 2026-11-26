// Demo: beta label and the one-time beta note.
// The projects screen shows the note until it is dismissed (stored in settings.ui.beta_note_done);
// "Report a problem" saves the logs ZIP and opens the GitHub new-issue page; Settings and About show a
// "Beta" chip next to the version and About repeats "Report a problem". EN and UK texts are checked too.
// qa/shoot.sh --routes none --out $PWD/qa/out/beta-note --steps $PWD/qa/scenarios/beta-note/steps.mjs
import fs from "fs";
export default async (page, { out }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const text = sel => ev(s => { const e = document.querySelector(s); return e ? e.textContent.replace(/\s+/g, " ").trim() : null; }, sel);
  const shot = name => page.screenshot({ path: `${out}/beta_${name}.png` }).catch(() => {});
  const ISSUES = "https://github.com/SinonApp/FOCA-rs/issues/new/choose";
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => { FOCA.api.terms_accept("1"); localStorage.setItem("foca-welcomed", "1"); });
    await ev(() => FOCA.i18n && FOCA.i18n.setLang("ru")); await wait(200);
    // Record what "Report a problem" does instead of opening a tab.
    await ev(() => {
      window.__opened = [];
      window.open = u => { window.__opened.push(String(u)); return null; };
      window.__calls = [];
      for (const k of ["logs_export", "platform_save"]) {
        const f = FOCA.api[k];
        FOCA.api[k] = (...a) => { window.__calls.push(k); return f(...a); };
      }
    });

    await ev(() => FOCA.reset(["/projects"])); await wait(600);
    const note = await text(".beta-note");
    ok("projects screen shows the beta note", /бета-версия/.test(note || "") && /сообщайте о проблемах/.test(note || ""), note);
    ok("note has Report a problem and Got it", /Сообщить о проблеме/.test(note || "") && /Понятно/.test(note || ""), note);
    const geo = await ev(() => {
      const c = document.querySelector(".beta-note");
      if (!c) return null;
      const btns = [...c.querySelectorAll("button")].map(b => { const r = b.getBoundingClientRect(); return [Math.round(r.width), Math.round(r.height)]; });
      return { over: c.scrollWidth - c.clientWidth, btns };
    });
    ok("note does not overflow and its buttons are 44 px tap targets", !!geo && geo.over === 0 && geo.btns.every(([w, h]) => w >= 44 && h >= 44), geo);
    await shot("note_ru");

    // Settings and About: the Beta chip next to the version.
    await ev(() => FOCA.go("/settings")); await wait(600);
    ok("Settings shows the Beta chip in the About row", !!(await ev(() => document.querySelector('[data-act="st-go:/settings/about"] .beta-chip'))), await text('[data-act="st-go:/settings/about"]'));
    await ev(() => FOCA.go("/settings/about")); await wait(700);
    const ver = await text("#st-ab-v");
    ok("About shows the version with the Beta chip", /\d+\.\d+\.\d+-beta\.\d+/.test(ver || "") && /Бета/.test(ver || ""), ver);
    ok("About offers Report a problem", !!(await ev(() => document.querySelector('[data-act="beta-report-about"]'))));
    await shot("about_ru");

    // Report a problem from the note: logs ZIP saved, GitHub issue form opened, note dismissed.
    await ev(() => FOCA.go("/projects")); await wait(600);
    await page.click('.beta-note [data-act="beta-report"]'); await wait(1200);
    const calls = await ev(() => window.__calls);
    ok("logs are exported and saved to Downloads", calls.includes("logs_export") && calls.includes("platform_save"), calls);
    ok("GitHub new-issue page opens", (await ev(() => window.__opened)).includes(ISSUES), await ev(() => window.__opened));
    ok("note is gone after reporting", (await text(".beta-note")) === null);
    ok("dismissal is stored in settings", (await ev(() => FOCA.api.settings_get())).ui.beta_note_done === true);
    await ev(() => FOCA.go("/settings/about")); await wait(400);
    await ev(() => FOCA.go("/projects")); await wait(500);
    ok("note stays hidden on the next visit", (await text(".beta-note")) === null);

    // "Got it" path, and EN / UK texts.
    for (const [lang, re, btn] of [["en", /This is a beta: some things may break/, /Report a problem/], ["uk", /Це бета-версія: дещо може зламатися/, /Повідомити про проблему/]]) {
      await ev(() => FOCA.api.settings_set({ ui: { beta_note_done: false } })); await wait(150);
      await ev(l => FOCA.i18n.setLang(l), lang); await wait(400);
      await ev(() => FOCA.go("/projects")); await wait(500);
      const t = await text(".beta-note");
      ok(`${lang}: note is translated`, re.test(t || "") && btn.test(t || ""), t);
      await shot(`note_${lang}`);
    }
    await page.click('.beta-note .beta-note-a [data-act="beta-dismiss"]'); await wait(500);
    ok("Got it dismisses the note", (await text(".beta-note")) === null && (await ev(() => FOCA.api.settings_get())).ui.beta_note_done === true);
    await ev(() => FOCA.go("/settings/about")); await wait(600);
    ok("uk: About chip is translated", /Бета/.test((await text("#st-ab-v")) || ""));
    await ev(() => FOCA.i18n.setLang("ru"));
  } catch (e) { fails++; log.push(["FAIL", "exception", String((e && e.stack) || e).slice(0, 500)]); }
  fs.writeFileSync(`${out}/beta_note_steps.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] ?? "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
