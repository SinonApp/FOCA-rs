// In-app update screen (/settings/update) in demo mode at phone widths, EN UI.
// States: up to date, update available (notes rendered escaped, schema warning, flavor asset),
// download with progress → verified → install permission flow → install, rate-limited (backoff
// time, no retry), verification failed (refused with the reason, no install button). Also checks
// the toggles persist, the About and Settings rows lead here, and nothing overflows horizontally.
// Run: qa/shoot.sh --routes none --out $PWD/qa/out/upd393 --w 393 --theme dark --steps $PWD/qa/scenarios/self-update/steps.mjs
//      qa/shoot.sh --routes none --out $PWD/qa/out/upd360 --w 360 --fs 2 --theme light --steps $PWD/qa/scenarios/self-update/steps.mjs
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
    await FOCA.api.update_cancel();
  });
  await prep();
  await page.evaluate(() => FOCA.i18n.setLang("en"));
  await page.waitForTimeout(250);

  const text = () => page.evaluate(() => document.querySelector(".page").innerText);
  const noOverflow = async name => {
    const o = await page.evaluate(() => {
      const se = document.scrollingElement;
      const pg = document.querySelector(".page") || se;
      return { sw: Math.max(se.scrollWidth, pg.scrollWidth), cw: se.clientWidth };
    });
    check(`${name}: no horizontal overflow (${tag})`, o.sw <= o.cw + 1, JSON.stringify(o));
  };
  const noCyrillic = async name => {
    const t = await text();
    const m = t.match(/[А-Яа-яЁёЇїІіЄєҐґ]+/g);
    check(`${name}: no Cyrillic in the EN UI`, !m, m && m.slice(0, 5).join(" "));
  };
  const open = async () => {
    await page.evaluate(() => FOCA.go("/settings/update"));
    await page.waitForTimeout(450);
  };
  const demoCheck = async state => {
    await page.evaluate(async s => {
      await FOCA.api.update_check({ flavor: "foss", demo_state: s });
    }, state);
    await page.evaluate(() => FOCA.actions["upd-check"]());
    await page.waitForTimeout(450);
  };

  // ---- Entry points ----
  await page.evaluate(() => FOCA.go("/settings/about"));
  await page.waitForTimeout(400);
  check("About has an Updates row", !!(await page.$('[data-act="go:/settings/update"]')));
  await page.evaluate(() => FOCA.go("/settings"));
  await page.waitForTimeout(400);
  check("Settings has an Updates row", !!(await page.$('[data-act="st-go:/settings/update"]')));

  // ---- Never checked, then up to date ----
  await open();
  let t = await text();
  check("never checked before the first check", t.includes("Not checked yet"), t.slice(0, 200));
  check("installed version and flavor shown", t.includes("Installed: 2.0.0-beta.4.1 (FOSS)"), t.slice(0, 300));
  check("privacy note names the hosts", t.includes("api.github.com") && t.includes("User-Agent"));
  await demoCheck("up_to_date");
  t = await text();
  check("up to date status", t.includes("You have the latest version"), t.slice(0, 200));
  check("no release card when up to date", !(await page.$("#upd-rel")));
  await noCyrillic("up to date");
  await noOverflow("up to date");
  await page.screenshot({ path: `${out}/update-uptodate-${tag}.png`, fullPage: true });

  // ---- Toggles persist through settings_set ----
  const before = await page.evaluate(() => FOCA.state.upd.view.settings.wifi_only);
  await page.click('.row[data-act="upd-set:wifi_only"]');
  await page.waitForTimeout(400);
  const saved = await page.evaluate(async () => (await FOCA.api.update_status("foss")).settings.wifi_only);
  check("Wi-Fi only toggle saved", saved === !before, JSON.stringify({ before, saved }));
  await page.click('.row[data-act="upd-set:wifi_only"]');
  await page.waitForTimeout(400);

  // ---- Update available ----
  await demoCheck("available");
  t = await text();
  check("available status names the version", t.includes("Version 2.0.0-beta.5 is available"), t.slice(0, 200));
  check("flavor-matched asset", t.includes("FOCA-rs-2.0.0-beta.5-foss-arm64.apk"));
  check("date in the app format", t.includes("05.12.2026"));
  check("size in MB", /43\.3 MB/.test(t), t);
  check("schema warning before install", !!(await page.$("#upd-schema")) && t.includes("previous version cannot open them"));
  const notes = await page.evaluate(() => {
    const n = document.querySelector(".upd-notes");
    return { h: n.querySelectorAll("h4").length, li: n.querySelectorAll("li").length, b: n.querySelectorAll("b").length, a: n.querySelectorAll("a,img,script").length };
  });
  check("notes rendered as headings, list and bold", notes.h === 2 && notes.li === 3 && notes.b === 1, JSON.stringify(notes));
  check("notes contain no links, images or scripts", notes.a === 0);
  const escaped = await page.evaluate(() => {
    const h = FOCA.safeMd("## T\n- <img src=x onerror=alert(1)> [x](https://example.com)");
    return { raw: /<img/i.test(h), esc: h.includes("&lt;img") };
  });
  check("remote markup is escaped by the shared renderer", !escaped.raw && escaped.esc, JSON.stringify(escaped));
  await noCyrillic("available");
  await noOverflow("available");
  await page.screenshot({ path: `${out}/update-available-${tag}.png`, fullPage: true });

  // ---- Download, progress, verified ----
  await page.evaluate(() => FOCA.actions["upd-download"]());
  await page.waitForTimeout(400);
  const prog = await page.evaluate(() => {
    const el = document.querySelector("#upd-prog");
    return el ? el.innerText : "";
  });
  check("progress shown while downloading", /Downloading \d+%/.test(prog), prog);
  await page.screenshot({ path: `${out}/update-progress-${tag}.png` });
  await page.waitForTimeout(1200);
  t = await text();
  check("verified banner after download", t.includes("signature and checksum are verified"), t.slice(0, 600));
  check("install permission asked first", !!(await page.$('[data-act="upd-perm"]')));
  await noOverflow("verified");
  await page.screenshot({ path: `${out}/update-permission-${tag}.png`, fullPage: true });
  await page.evaluate(() => FOCA.actions["upd-perm"]());
  await page.waitForTimeout(300);
  check("install button after the permission", !!(await page.$('[data-act="upd-install"]')));
  await page.evaluate(() => FOCA.actions["upd-install"]());
  await page.waitForTimeout(300);
  const sheet = await page.evaluate(() => (document.querySelector(".sheet") || {}).innerText || "");
  check("schema confirmation sheet before install", sheet.includes("project format will change"), sheet);
  await page.screenshot({ path: `${out}/update-schema-sheet-${tag}.png` });
  await page.evaluate(() => FOCA.actions["upd-install-go"]());
  await page.waitForTimeout(300);
  const snack = await page.evaluate(() => (document.querySelector(".snack") || {}).innerText || "");
  check("install hands over to Android", snack.includes("Confirm the installation"), snack);
  await page.evaluate(() => FOCA.actions["upd-cancel"]());
  await page.waitForTimeout(300);

  // ---- Rate limited ----
  await demoCheck("rate_limited");
  t = await text();
  check("rate limit status with the retry time", /GitHub request limit\. Retry after \d\d:\d\d/.test(t), t.slice(0, 300));
  await noCyrillic("rate limited");
  await noOverflow("rate limited");
  await page.screenshot({ path: `${out}/update-ratelimited-${tag}.png`, fullPage: true });

  // ---- Verification failed ----
  await page.evaluate(() => {
    const st = FOCA_DEMO_BACKEND._state();
    st._upd.backoff_until = null;
    st._upd.error = null;
  });
  await demoCheck("verify_failed");
  await page.evaluate(() => FOCA.actions["upd-download"]());
  await page.waitForTimeout(1600);
  t = await text();
  check("verification failure is refused with the reason", !!(await page.$("#upd-fail")) && t.includes("release signature did not verify"), t.slice(0, 700));
  check("no install button after a failed verification", !(await page.$('[data-act="upd-install"]')));
  await noCyrillic("verify failed");
  await noOverflow("verify failed");
  await page.screenshot({ path: `${out}/update-failed-${tag}.png`, fullPage: true });

  // ---- UK and RU texts load ----
  for (const [lang, word] of [
    ["uk", "Перевірити оновлення"],
    ["ru", "Проверить обновления"],
  ]) {
    await page.evaluate(l => FOCA.i18n.setLang(l), lang);
    await page.waitForTimeout(250);
    await open();
    t = await text();
    check(`${lang}: check button translated`, t.includes(word), t.slice(0, 200));
    await noOverflow(`${lang} screen`);
  }
  await page.evaluate(() => FOCA.i18n.setLang("en"));
  await page.evaluate(() => FOCA.api.update_cancel());

  console.log(`${res.ok} OK, ${res.fail} FAIL`);
};
