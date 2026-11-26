// Signature databases screen and the API key sheet at phone widths (393 dark fs1, 360 light fs2), UK UI.
// Signatures: the Ed25519 chip stays on one line, dates are in the app format (20.11.2026) and never
// split, the KEV row says CISA KEV (no NVD) with the used/total numbers, the standards row lists the
// families from the mapping, "Check for updates" reports "not published yet" and records the last
// check instead of claiming an update. Key sheet: the "Check key" button keeps the form gap under the
// key field. No horizontal overflow anywhere.
// Run: qa/shoot.sh --routes none --out $PWD/qa/out/sig393 --w 393 --theme dark --steps $PWD/qa/scenarios/signatures-screen/steps.mjs
//      qa/shoot.sh --routes none --out $PWD/qa/out/sig360 --w 360 --fs 2 --theme light --steps $PWD/qa/scenarios/signatures-screen/steps.mjs
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
    // Fresh signature state: no bundle, never checked (the demo state object is live).
    const st = FOCA_DEMO_BACKEND._state();
    delete st._sigBundle;
    delete st._sigPrev;
    delete st._sigCheck;
  });
  await prep();
  await page.evaluate(() => FOCA.i18n.setLang("uk"));
  await page.waitForTimeout(250);

  const noOverflow = async name => {
    const o = await page.evaluate(() => {
      const se = document.scrollingElement;
      const pg = document.querySelector(".page") || se;
      return { sw: Math.max(se.scrollWidth, pg.scrollWidth), cw: se.clientWidth };
    });
    check(`${name}: no horizontal overflow (${tag})`, o.sw <= o.cw + 1, JSON.stringify(o));
  };
  // A single-line inline element: one client rect whose height is below 1.6 line heights.
  const oneLine = sel =>
    page.evaluate(sel => {
      const el = document.querySelector(sel);
      if (!el) return { found: false };
      const lh = parseFloat(getComputedStyle(el).lineHeight) || parseFloat(getComputedStyle(el).fontSize) * 1.3;
      const rects = el.getClientRects().length;
      return { found: true, rects, h: el.getBoundingClientRect().height, lh, text: el.textContent };
    }, sel);

  // ---- Signatures screen, built-in database ----
  await page.evaluate(() => {
    FOCA.state.sigBundle.data = null;
    FOCA.go("/settings/signatures");
  });
  await page.waitForTimeout(500);
  const t0 = await page.evaluate(() => document.querySelector(".page").innerText);
  check("title column shows the app date format", t0.includes("20.11.2026"), t0.slice(0, 200));
  check("no raw ISO date in the header", !/2026-11-20/.test(t0));
  const d0 = await oneLine(".st-sigtop-t .st-nw");
  check(`header date on one line (${tag})`, d0.found && d0.rects === 1, JSON.stringify(d0));
  check("built-in database has no Ed25519 chip", !(await page.$(".st-sigpill")));
  check("KEV row: CISA KEV, no NVD", t0.includes("CISA KEV") && !t0.includes("NVD"));
  check("KEV row: used of total", /924\D+1\s?790/.test(t0.replace(/\u00a0/g, " ")), t0);
  check("KEV row: catalog date and age", /Каталог від 20\.11\.2026/.test(t0) && /(тому|сьогодні)/.test(t0));
  check("software row: 73 signatures split 54 + 19", /73 сигнатури/.test(t0) && t0.includes("ПЗ: 54, ОС: 19"), t0);
  check("secrets row: 24 rules", t0.includes("24 правила"));
  check("standards row: 438 mappings for 74 rules", /438 зіставлень/.test(t0.replace(/\u00a0/g, " ")) && t0.includes("74 правила знахідок"));
  for (const fw of ["OWASP Top 10:2025", "MITRE ATT&CK v20", "CWE (Top 25 2025)", "НД ТЗІ 3.6-006-24", "NIST SP 800-53", "GDPR", "2297-VI", "застарілі, КСЗІ"]) {
    check(`standards row lists ${fw}`, t0.includes(fw));
  }
  check("old hard-coded labels are gone", !t0.includes("MITRE/CWE/OWASP/КСЗІ") && !t0.includes("Оновлювати автоматично"));
  check("last check: never before the first check", t0.includes("ще не перевірялося"));
  check("button says Check for updates", t0.includes("Перевірити оновлення"));
  await noOverflow("signatures");
  await page.screenshot({ path: `${out}/signatures-builtin-${tag}.png`, fullPage: true });
  await page.evaluate(() => document.querySelector(".st-siglist").scrollIntoView({ block: "start" }));
  await page.waitForTimeout(200);
  await page.screenshot({ path: `${out}/signatures-list-${tag}.png` });
  await page.evaluate(() => [...document.querySelectorAll(".st-siglist .row")].pop().scrollIntoView({ block: "start" }));
  await page.waitForTimeout(200);
  await page.screenshot({ path: `${out}/signatures-standards-${tag}.png` });
  const split = await page.evaluate(() =>
    [...document.querySelectorAll(".st-siglist .st-nw")].filter(e => e.getClientRects().length > 1).map(e => e.textContent),
  );
  check(`dates and document codes in the rows are never split (${tag})`, split.length === 0, split.join(" | "));

  // ---- Check for updates: nothing published, honest result ----
  await page.click('[data-act="st-sigupd"]');
  await page.waitForTimeout(600);
  const t1 = await page.evaluate(() => document.querySelector(".page").innerText);
  const snack = await page.evaluate(() => (document.querySelector(".snack, #snack, .toast") || {}).innerText || "");
  check("last check shows not published yet", t1.includes("нову базу ще не опубліковано"), t1.slice(0, 400));
  check("snack says nothing was published", /не опубліковано/.test(snack), snack);
  check("no success claim", !/оновлено|встановлено/i.test(snack + t1.split("Остання перевірка")[1]?.slice(0, 80)));
  const lc = await oneLine("#st-siglast .st-nw");
  check(`last check time on one line (${tag})`, lc.found && lc.rects === 1, JSON.stringify(lc));

  // ---- Installed bundle: the Ed25519 chip stays on one line ----
  await page.evaluate(async () => {
    await FOCA.api.signatures_import(
      JSON.stringify({
        schema: "foca-sig-bundle/v1",
        version: "2026.11.24",
        released_at: "2026-11-24",
        counts: { cpe: 0, cve: 0, secrets: 0, standards: 0 },
        kev_additions: [{ cve: "CVE-2099-0001", product_key: "php", vendor: "PHP", product: "PHP", date_added: "2026-11-24", name: "Sample" }],
        secret_additions: [{ id: "sig_sample", title: "Sample", pattern: "smp_[a-z]{20}" }],
        sha256: "00",
        signature_ed25519: "11",
      }),
    );
    FOCA.state.sigBundle.data = null;
    FOCA.render(true);
  });
  await page.waitForTimeout(500);
  const pill = await oneLine(".st-sigpill");
  check(`Ed25519 chip on one line (${tag})`, pill.found && pill.rects === 1 && pill.h < pill.lh * 1.6 + 8, JSON.stringify(pill));
  check("chip text intact", pill.text === "Ed25519 OK", pill.text);
  const overlap = await page.evaluate(() => {
    const a = document.querySelector(".st-sigpill").getBoundingClientRect();
    const r = document.createRange();
    r.selectNodeContents(document.querySelector(".st-sigtop-t"));
    // Text boxes of the title column, not the column box (which may be wider than its words).
    return [...r.getClientRects()].some(b => b.width > 0 && a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1);
  });
  check(`chip does not overlap the title text (${tag})`, !overlap);
  const t2 = await page.evaluate(() => document.querySelector(".page").innerText);
  check("bundle date in the app format", t2.includes("24.11.2026"));
  check("bundle KEV entry counted once", /925\D+1\s?790/.test(t2.replace(/\u00a0/g, " ")));
  check("bundle secret rule counted in the total", t2.includes("25 правил") && t2.includes("зокрема 1 з пакета"));
  const d2 = await oneLine(".st-sigtop-t .st-nw");
  check(`bundle header date on one line (${tag})`, d2.found && d2.rects === 1, JSON.stringify(d2));
  await noOverflow("signatures with bundle");
  await page.screenshot({ path: `${out}/signatures-bundle-${tag}.png`, fullPage: true });
  await page.evaluate(() => FOCA.api.signatures_rollback());

  // ---- API key sheet: gap between the key field and "Check key" ----
  await page.evaluate(() => FOCA.go("/settings/keys"));
  await page.waitForTimeout(400);
  await page.click('[data-act="st-key:shodan"]');
  await page.waitForTimeout(500);
  const gap = await page.evaluate(() => {
    const f = document.querySelector(".st-kfield"),
      b = document.querySelector(".st-kcheck");
    if (!f || !b) return null;
    return { gap: b.getBoundingClientRect().top - f.getBoundingClientRect().bottom, css: getComputedStyle(b).marginTop };
  });
  check(`key sheet with a check result: button keeps the form gap (${tag})`, gap && gap.gap >= 11, JSON.stringify(gap));
  // A key without a check result: the empty result line is hidden, the button sits right under the field.
  const gap2 = await page.evaluate(() => {
    document.getElementById("st-kres").innerHTML = "";
    const f = document.querySelector(".st-kfield"),
      b = document.querySelector(".st-kcheck");
    return { gap: b.getBoundingClientRect().top - f.getBoundingClientRect().bottom };
  });
  check(`key sheet without a result: button keeps the form gap (${tag})`, gap2.gap >= 11, JSON.stringify(gap2));
  await page.evaluate(() => document.querySelectorAll(".snack, .toast, #snack").forEach(e => e.remove()));
  await page.screenshot({ path: `${out}/key-sheet-${tag}.png` });

  console.log(`${res.ok} OK, ${res.fail} FAIL`);
};
