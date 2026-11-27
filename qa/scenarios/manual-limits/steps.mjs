// Manual numeric settings without hard caps (ui/js/limits.js): big values are accepted and saved,
// an inline warning appears past the recommended range, risky values (very high speed, threads or
// hosts at once, no speed limit, unlimited mobile data) ask for a one-time confirmation, and every
// traffic cap can be removed. Covers Settings → Network, Traffic and power, Wordlists, the OCR card
// and the launch wizard limits (demo backend).
// qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/manual-limits/steps.mjs
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
    await page.screenshot({ path: `${out}/manual-limits_${n}_${tag}.png` });
  };
  const overflow = () =>
    ev(() => {
      const p = FOCA.page() || document.body;
      return Math.max(document.documentElement.scrollWidth - innerWidth, p.scrollWidth - p.clientWidth);
    });
  const core = () => ev(() => FOCA.api.settings_get());
  const type = async (id, v) => {
    await ev(id => document.querySelector("#nf-" + id)?.scrollIntoView({ block: "center" }), id);
    await page.fill("#nf-" + id, String(v));
    await page.press("#nf-" + id, "Enter");
    await wait(450);
  };
  const warnOf = id =>
    ev(id => {
      const e = document.querySelector(`#nf-${id}-w`);
      return e && !e.hidden ? e.textContent.trim() : "";
    }, id);
  const sheetOpen = sel => ev(sel => !!document.querySelector(`.sheet.show ${sel}`), sel);
  const confirm = async sel => {
    await ev(sel => document.querySelector(`.sheet.show ${sel}`)?.click(), sel);
    await wait(700);
  };

  await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href);
  await wait(400);
  await ev(() => FOCA.api.demo_reset());
  await wait(150);
  await ev(() => FOCA.api.terms_accept("1"));
  await ev(() => FOCA.api.project_open("contoso"));
  await wait(200);
  if (prep) await prep(); // our own page.goto dropped the font scale and theme

  // ---- Settings → Network ----
  await go("/settings/network");
  await type("net-rps", 30);
  ok("rps 30 is saved as typed", (await core()).net.rps === 30, (await core()).net);
  ok("rps 30 shows the inline warning", /20/.test(await warnOf("net-rps")), await warnOf("net-rps"));
  ok("rps 30 needs no confirmation", !(await sheetOpen('[data-act="nf-risk-ok"]')));
  await shot("net_warning");
  await type("net-threads", 200);
  ok("threads 200 open the confirm sheet", await sheetOpen('[data-act="nf-risk-ok"]'));
  await shot("net_confirm");
  await confirm('[data-act="nf-risk-ok"]');
  ok("threads 200 are saved after confirming", (await core()).net.threads === 200, (await core()).net);
  ok("threads 200 keep the warning", /16/.test(await warnOf("net-threads")), await warnOf("net-threads"));
  await type("net-rps", 0);
  ok("rps 0 (no limit) asks for confirmation", await sheetOpen('[data-act="nf-risk-ok"]'));
  await ev(() => FOCA.closeSheet());
  await wait(400);
  ok("cancel keeps rps 30", (await core()).net.rps === 30 && (await ev(() => document.querySelector("#nf-net-rps").value)) === "30");
  await type("net-rps", 0);
  await confirm('[data-act="nf-risk-ok"]');
  ok("rps 0 is saved after confirming", (await core()).net.rps === 0, (await core()).net);
  ok(
    "rps 0 shows the 'no limit' pill",
    await ev(() => /без лимита/.test(document.querySelector('.nf[data-nf="net-rps"] .nf-rec')?.textContent || "")),
  );
  await type("net-hostsParallel", 40);
  await confirm('[data-act="nf-risk-ok"]');
  ok("40 hosts at once are saved", (await core()).net.hosts_parallel === 40, (await core()).net);
  await type("net-timeout", 600);
  ok("timeout 600 s is saved with a warning", (await core()).net.timeout === 600 && /120/.test(await warnOf("net-timeout")));
  await type("net-threads", 0);
  ok("threads 0 is refused (hard minimum)", (await core()).net.threads === 200, (await core()).net);
  ok("no horizontal overflow on Settings → Network", (await overflow()) <= 1, await overflow());
  await ev(() => FOCA.actions["st-preset"]("normal"));
  await ev(() => FOCA.api.settings_set({ net: { hosts_parallel: 4, retries: 2 } }));
  await wait(300);

  // ---- Traffic and power: every cap removable ----
  await go("/settings/power");
  await type("power-mobLimit", 0);
  let s = await core();
  ok("mobile cap 0 is saved while Wi-Fi only is on (no confirm)", s.power.mob_limit === 0 && !(await sheetOpen('[data-act="nf-risk-ok"]')), s.power);
  ok("mobile cap 0 shows the warning", /трафик/.test(await warnOf("power-mobLimit")), await warnOf("power-mobLimit"));
  await ev(() => document.querySelector('[data-act="st-t:power.wifiOnly"]').click());
  await wait(400);
  ok("Wi-Fi only off without a cap asks to confirm", await sheetOpen('[data-act^="st-mob-unlim"]'));
  await shot("power_confirm");
  await confirm('[data-act^="st-mob-unlim"]');
  ok("Wi-Fi only is off after confirming", (await core()).power.wifi_only === false);
  await ev(() => document.querySelector('[data-act="st-t:power.limOn"]').click());
  await wait(400);
  await confirm('[data-act^="st-mob-unlim"]');
  s = await core();
  ok("the mobile cap switch can be turned off", s.power.lim_on === false, s.power);
  ok("an inline warning stays on the screen", await ev(() => !!document.querySelector(".st-mob-warn")));
  await type("power-batt", 70);
  ok("battery threshold 70% from the manual field", (await core()).power.batt === 70 && /50/.test(await warnOf("power-batt")));
  ok("no horizontal overflow on Traffic and power", (await overflow()) <= 1, await overflow());
  await shot("power");

  // ---- Wordlists: brute-force budgets ----
  await go("/settings/wordlists");
  await type("wl-rate", 15);
  ok("brute-force rate 15 saved with a warning", (await core()).fuzz.rate === 15 && /10/.test(await warnOf("wl-rate")));
  await type("wl-max_requests", 0);
  await type("wl-max_hosts", 50);
  s = await core();
  ok("request budget 0 (no limit) and 50 addresses saved", s.fuzz.max_requests === 0 && s.fuzz.max_hosts === 50, s.fuzz);
  ok("no horizontal overflow on Wordlists", (await overflow()) <= 1, await overflow());
  await shot("wordlists");

  // ---- OCR card ----
  await go("/settings/signatures");
  await type("ocr-max_pages", 200);
  ok("OCR page cap 200 saved (old max 30)", (await core()).ocr.max_pages === 200, (await core()).ocr);

  // ---- Launch wizard limits ----
  await ev(() => {
    FOCA.state.launch.leave = true;
    FOCA.go("/new");
  });
  await wait(450);
  if (!(await ev(() => FOCA.state.launch.adv))) await ev(() => FOCA.actions["la-adv"]());
  await wait(300);
  await type("la-maxDocs", 20000);
  await type("la-maxSize", 0);
  await type("la-depth", 8);
  ok("wizard: 20000 documents warn", /5000/.test(await warnOf("la-maxDocs")), await warnOf("la-maxDocs"));
  ok("wizard: size 0 = no limit", /без лимита/.test(await ev(() => document.querySelector('.nf[data-nf="la-maxSize"] .nf-rec')?.textContent || "")));
  const sent = await ev(() => {
    let got = null;
    const orig = FOCA.api.scan_start;
    FOCA.api.scan_start = a => {
      got = a;
      return Promise.reject(new Error("stub"));
    };
    try {
      FOCA.actions["la-start"]();
    } finally {
      FOCA.api.scan_start = orig;
    }
    return got && { limit: got.limit, max_size_mb: got.max_size_mb, crawl_depth: got.crawl_depth };
  });
  ok("wizard sends the typed limits", sent && sent.limit === 20000 && sent.max_size_mb === 0 && sent.crawl_depth === 8, sent);
  ok("no horizontal overflow in the wizard", (await overflow()) <= 1, await overflow());
  await ev(() => document.querySelector('.nf[data-nf="la-maxDocs"]')?.scrollIntoView({ block: "center" }));
  await shot("wizard");

  // ---- the same warnings in EN and UK ----
  for (const [l, re] of [
    ["en", /Above 20 req\/s/],
    ["uk", /Понад 20 запитів/],
  ]) {
    await ev(l => FOCA.i18n.setLang(l), l);
    await wait(500);
    await ev(() => FOCA.api.settings_set({ net: { rps: 30 } }));
    await go("/settings/network");
    ok(`rps warning in ${l}`, re.test(await warnOf("net-rps")), await warnOf("net-rps"));
  }
  await ev(() => FOCA.i18n.setLang("auto"));
  await ev(() => FOCA.api.demo_reset());
  await wait(300);
  console.log(`${oks} OK, ${fails} FAIL`);
};
