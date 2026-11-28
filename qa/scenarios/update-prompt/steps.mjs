// Start-up update dialog and the automatic signature update settings, demo mode, EN UI.
// Dialog: shown for a new release with version, date, size and a few plain note lines; "Later"
// suppresses it for that version; "Settings" and "Update" lead into the regular update screen
// (Update starts the verified download); the "Ask on start" setting turns it off; a rate-limited
// check shows nothing; automated runs never get it on their own. Signatures: off/daily/weekly,
// Wi-Fi only, next check.
// Run: qa/shoot.sh --routes none --out $PWD/qa/out/updp393 --w 393 --theme dark --steps $PWD/qa/scenarios/update-prompt/steps.mjs
//      qa/shoot.sh --routes none --out $PWD/qa/out/updp360 --w 360 --fs 2 --theme light --steps $PWD/qa/scenarios/update-prompt/steps.mjs
const res = { ok: 0, fail: 0 };
const check = (label, cond, detail = "") => {
  if (cond) res.ok++;
  else res.fail++;
  console.log(`${cond ? "OK  " : "FAIL"} ${label}${!cond && detail ? " - " + detail : ""}`);
};

export default async (page, { out, go, prep, W, fsc }) => {
  const tag = `${W}-fs${fsc}`;
  await go("/projects");
  await page.evaluate(async () => {
    localStorage.setItem("foca-welcomed", "1");
    const t = await FOCA.api.terms_get();
    if (!t.accepted) await FOCA.api.terms_accept(t.version);
    const st = FOCA_DEMO_BACKEND._state();
    delete st._upd;
    delete st._sigAuto;
    await FOCA.api.settings_set({ update: { auto: true, prompt: true, prompted: "" } });
    await FOCA.api.update_cancel();
  });
  await prep();
  await page.evaluate(() => FOCA.i18n.setLang("en"));
  await page.waitForTimeout(300);

  const sheetText = () => page.evaluate(() => (document.querySelector(".sheet") || {}).innerText || "");
  const sheetOpen = () => page.evaluate(() => !!document.querySelector("#upd-prompt"));
  const prompted = () => page.evaluate(async () => (await FOCA.api.update_status("foss")).settings.prompted);
  const resetPrompted = () =>
    page.evaluate(async () => {
      await FOCA.api.settings_set({ update: { prompted: "" } });
    });
  const run = async () => {
    await page.evaluate(() => FOCA.updateAutoCheck(true));
    await page.waitForTimeout(500);
  };
  const noOverflow = async name => {
    const o = await page.evaluate(() => {
      const el = document.querySelector(".sheet") || document.querySelector(".page");
      const wide = [...el.querySelectorAll("*")].filter(e => e.getBoundingClientRect().right > innerWidth + 1);
      return { wide: wide.length, first: wide[0] ? wide[0].tagName + "." + wide[0].className : "" };
    });
    check(`${name}: nothing past the right edge (${tag})`, o.wide === 0, JSON.stringify(o));
  };

  // ---- Automated runs never get the dialog by themselves ----
  await page.waitForTimeout(3500);
  check("no dialog on its own under automation", !(await sheetOpen()));

  // ---- Shown once for a new version ----
  await run();
  let t = await sheetText();
  check("dialog shown for the new version", await sheetOpen(), t);
  check("title names the version", t.includes("Version 2.0.0-beta.5 is available"), t.slice(0, 120));
  check("release date in the app format", t.includes("05.12.2026"), t);
  check("size in MB", /43\.3 MB/.test(t), t);
  const lines = await page.evaluate(() => [...document.querySelectorAll("#upd-prompt .upd-plines li")].map(l => l.textContent));
  check("3 to 5 note lines", lines.length >= 3 && lines.length <= 5, JSON.stringify(lines));
  check("notes are plain text (no Markdown markers)", lines.every(l => !/[#*_`<>]/.test(l)), JSON.stringify(lines));
  check("headings are skipped", !lines.some(l => /^(Added|Fixed)$/.test(l)), JSON.stringify(lines));
  const btns = await page.evaluate(() => [...document.querySelectorAll(".sheet [data-act]")].map(b => b.dataset.act));
  check(
    "Update, Later and Settings buttons",
    ["upd-prompt-go", "upd-later", "upd-prompt-settings"].every(a => btns.includes(a)),
    JSON.stringify(btns),
  );
  check("no Cyrillic in the EN dialog", !/[А-Яа-яЁёЇїІіЄєҐґ]/.test(t), t);
  await noOverflow("dialog");
  await page.screenshot({ path: `${out}/update-prompt-${tag}.png` });
  check("the version is stored as asked", (await prompted()) === "2.0.0-beta.5");

  // ---- Later: not asked again for this version ----
  await page.click('.sheet [data-act="upd-later"]');
  await page.waitForTimeout(400);
  check("Later closes the dialog", !(await sheetOpen()));
  await run();
  check("Later suppresses the dialog for that version", !(await sheetOpen()));

  // ---- Settings leads to the updates screen with the setting ----
  await resetPrompted();
  await run();
  await page.click('.sheet [data-act="upd-prompt-settings"]');
  await page.waitForTimeout(600);
  check("Settings opens the updates screen", await page.evaluate(() => FOCA.cur.path === "/settings/update"));
  const row = await page.$('.row[data-act="upd-set:prompt"]');
  check("Ask on start setting on the updates screen", !!row);
  t = await page.evaluate(() => document.querySelector(".page").innerText);
  check("setting label", t.includes("Ask on start when an update is available"), t.slice(-600));

  // ---- Update goes into the verified download ----
  await page.evaluate(() => FOCA.go("/projects"));
  await page.waitForTimeout(300);
  await resetPrompted();
  await run();
  await page.click('.sheet [data-act="upd-prompt-go"]');
  await page.waitForTimeout(500);
  const onUpd = await page.evaluate(() => FOCA.cur.path);
  const dl = await page.evaluate(() => (FOCA.state.upd.view || {}).download || {});
  check("Update opens the updates screen", onUpd === "/settings/update", onUpd);
  check("Update starts the download", ["download", "verify", "ready"].includes(dl.phase) || !!(await page.$("#upd-prog")), JSON.stringify(dl));
  await page.waitForTimeout(1300);
  t = await page.evaluate(() => document.querySelector(".page").innerText);
  check("download is verified before install", t.includes("signature and checksum are verified"), t.slice(0, 500));
  await page.evaluate(() => FOCA.actions["upd-cancel"]());
  await page.waitForTimeout(300);

  // ---- Setting off: never asked ----
  await page.click('.row[data-act="upd-set:prompt"]');
  await page.waitForTimeout(400);
  const off = await page.evaluate(async () => (await FOCA.api.update_status("foss")).settings.prompt);
  check("Ask on start toggle saved", off === false, String(off));
  await page.evaluate(() => FOCA.go("/projects"));
  await page.waitForTimeout(300);
  await resetPrompted();
  await run();
  check("no dialog with the setting off", !(await sheetOpen()));
  await page.evaluate(async () => {
    await FOCA.api.settings_set({ update: { prompt: true, prompted: "" } });
  });

  // ---- Rate limited: nothing shown ----
  await page.evaluate(async () => {
    await FOCA.api.update_check({ flavor: "foss", demo_state: "rate_limited" });
  });
  await run();
  const snack = await page.evaluate(() => (document.querySelector(".snack") || {}).innerText || "");
  check("no dialog when GitHub limits requests", !(await sheetOpen()));
  check("no error notice for a background check", !/GitHub/.test(snack), snack);
  await page.evaluate(() => {
    const st = FOCA_DEMO_BACKEND._state();
    delete st._upd;
  });

  // ---- UK and RU dialog texts ----
  for (const [lang, word] of [
    ["uk", "Пізніше"],
    ["ru", "Позже"],
  ]) {
    await page.evaluate(l => FOCA.i18n.setLang(l), lang);
    await page.waitForTimeout(250);
    await resetPrompted();
    await run();
    t = await sheetText();
    check(`${lang}: dialog translated`, t.includes(word), t.slice(0, 200));
    await noOverflow(`${lang} dialog`);
    await page.evaluate(() => FOCA.closeSheet && FOCA.closeSheet());
    await page.waitForTimeout(300);
  }
  await page.evaluate(() => FOCA.i18n.setLang("en"));
  await page.waitForTimeout(250);

  // ---- Automatic signature updates ----
  await page.evaluate(() => FOCA.go("/settings/signatures"));
  await page.waitForTimeout(600);
  check("automatic update card", !!(await page.$("#st-sigauto")));
  t = await page.evaluate(() => document.querySelector(".page").innerText);
  check("daily by default", await page.evaluate(() => !!document.querySelector('[data-act="st-sigauto:daily"].on')));
  check("source and next check shown", t.includes("Next check") && t.includes("Built-in database"), t.slice(0, 900));
  const d1 = await page.evaluate(() => FOCA.sigAutoCheck(true));
  check("first automatic check runs (nothing published in the demo)", d1 && d1.outcome === "no_update", JSON.stringify(d1 && d1.outcome));
  const d2 = await page.evaluate(() => FOCA.sigAutoCheck(true));
  check("second automatic check waits for the interval", d2 && d2.skipped === "not_due", JSON.stringify(d2 && d2.skipped));
  await page.click('[data-act="st-sigauto:weekly"]');
  await page.waitForTimeout(500);
  const mode = await page.evaluate(async () => (await FOCA.api.signatures_status()).auto.mode);
  check("weekly saved", mode === "weekly", mode);
  await page.click('.row[data-act="st-sigwifi"]');
  await page.waitForTimeout(500);
  const wifi = await page.evaluate(async () => (await FOCA.api.signatures_status()).auto.wifi_only);
  check("Wi-Fi only toggle saved", wifi === false, String(wifi));
  await page.click('[data-act="st-sigauto:off"]');
  await page.waitForTimeout(500);
  t = await page.evaluate(() => document.querySelector("#st-signext").innerText);
  check("off: no next check", t.includes("automatic checks are off"), t);
  check("no Cyrillic on the EN signatures card", !/[А-Яа-яЁёЇїІіЄєҐґ]/.test(await page.evaluate(() => document.querySelector("#st-sigauto").innerText)));
  await noOverflow("signatures");
  await page.screenshot({ path: `${out}/sig-auto-${tag}.png`, fullPage: true });
  await page.evaluate(async () => {
    await FOCA.api.settings_set({ signatures: { auto: "daily", wifi_only: true } });
  });

  console.log(`${res.ok} OK, ${res.fail} FAIL`);
};
