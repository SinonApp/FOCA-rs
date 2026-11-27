// Demo: search resilience UI. Settings → Sources has the "Search depth and retries" card (Common
// Crawl depth, years, pacing, postponed dork retry) wired to settings.search; the API keys sheet checks
// the Brave key (monthly quota) and own SearXNG addresses (HTTPS public host) through key_check and says
// that Brave needs a card; the scan screen shows "N searches postponed, will retry" with "Retry now".
// RU and EN.
// qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/search-resilience/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = [];
  let fails = 0;
  const ok = (name, cond, data) => {
    if (!cond) fails++;
    log.push([cond ? "OK" : "FAIL", name, data]);
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const text = sel => ev(s => document.querySelector(s)?.textContent || "", sel);
  const click = sel => ev(s => document.querySelector(s)?.click(), sel);
  const cyr = s => /[а-яёіїєґ]/i.test(s);
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href);
    await wait(400);
    await ev(() => FOCA.api.demo_reset());
    await wait(150);
    await ev(() => FOCA.api.terms_accept("1"));
    await ev(() => FOCA.api.project_open("contoso"));
    await wait(250);

    for (const lang of ["ru", "en"]) {
      await ev(l => FOCA.i18n.setLang(l), lang);
      await wait(300);

      // Settings → Sources: depth card bound to settings.search.
      await ev(() => FOCA.go("/settings/sources"));
      await wait(400);
      const card = await text(".src-depth");
      ok(`${lang}: depth card present`, card.includes("Common Crawl"), card.slice(0, 120));
      ok(`${lang}: no years row for latest`, !(await ev(() => !!document.querySelector('[data-act^="src-set:cc_years"]'))));
      await click('[data-act="src-set:cc_depth:years"]');
      await wait(300);
      const s1 = await ev(() => FOCA.db.settings.search);
      ok(`${lang}: depth saved`, s1.cc_depth === "years", s1);
      ok(`${lang}: years row appears`, await ev(() => !!document.querySelector('[data-act="src-set:cc_years:5"]')));
      await click('[data-act="src-set:cc_years:5"]');
      await click('[data-act="src-set:dork_retry_min:60"]');
      await wait(300);
      const s2 = await ev(() => FOCA.api.settings_get().then(s => s.search));
      ok(`${lang}: years and retry stored in the backend`, s2.cc_years === 5 && s2.dork_retry_min === 60, s2);
      const hint = await text(".src-depth + .fhint");
      ok(`${lang}: hint names the 3 s pacing`, /3/.test(hint) && (lang !== "en" || !cyr(hint)), hint.slice(0, 80));
      if (lang === "ru") await page.screenshot({ path: `${out}/search-resilience_sources_${tag}.png`, fullPage: true });
      await click('[data-act="src-set:cc_depth:latest"]');
      await wait(200);

      // API keys: Brave needs a card; the check reports the monthly quota or a rejected key.
      await ev(() => FOCA.go("/settings/keys"));
      await wait(300);
      await click('[data-act="st-key:brave"]');
      await wait(300);
      const lead = await text(".st-klead");
      ok(`${lang}: Brave note mentions the card and ~1000 queries`, /1000/.test(lead) && (lang === "en" ? /card/.test(lead) : /карт/.test(lead)), lead);
      await ev(() => (document.getElementById("st-kv").value = "short"));
      await click('[data-act="st-kcheck:brave"]');
      await wait(1700);
      const bad = await text("#st-kres");
      ok(`${lang}: short Brave key rejected`, /401/.test(bad), bad);
      await ev(() => (document.getElementById("st-kv").value = "BSAq7Lr2xkP0dZt3ab12"));
      await click('[data-act="st-kcheck:brave"]');
      await wait(1700);
      const good = await text("#st-kres");
      ok(`${lang}: Brave quota shown`, /958/.test(good) && /1[\s ,.]?000/.test(good), good);
      await click('[data-act="sheet-close"]');
      await wait(300);

      // Own SearXNG: addresses must be HTTPS on a public host; every address gets its own line.
      await click('[data-act="st-key:searx"]');
      await wait(300);
      const lbl = await text('label[for="st-kv"]');
      ok(`${lang}: SearXNG field is about addresses`, lang === "en" ? /address/i.test(lbl) : /Адреса/.test(lbl), lbl);
      await ev(() => (document.getElementById("st-kv").value = "http://192.168.1.5:8080, https://search.example.org"));
      await click('[data-act="st-kcheck:searx"]');
      await wait(1700);
      const sx = await text("#st-kres");
      ok(`${lang}: private HTTP address refused, public HTTPS accepted`, /192\.168\.1\.5/.test(sx) && /https:\/\/search\.example\.org/.test(sx) && (lang === "en" ? /https:\/\//.test(sx) : true), sx);
      ok(`${lang}: SearXNG check text localized`, lang !== "en" || !cyr(sx), sx);
      if (lang === "ru") await page.screenshot({ path: `${out}/search-resilience_searx_${tag}.png` });
      await click('[data-act="sheet-close"]');
      await wait(300);

      // Scan: Startpage hit a captcha, the spreadsheet dorks are postponed; "Retry now" clears them.
      await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "passive" }));
      await wait(300);
      await ev(() => FOCA.api.scan_pause());
      await ev(() => FOCA.go("/p/scan"));
      await wait(500);
      const ban = await text(".scn-dorks");
      ok(`${lang}: postponed banner`, (lang === "en" ? /postponed/ : /отложен/).test(ban), ban);
      ok(`${lang}: banner localized`, lang !== "en" || !cyr(ban), ban);
      ok(`${lang}: retry button`, await ev(() => !!document.querySelector('[data-act="scan-dorks-retry"]')));
      if (lang === "ru") await page.screenshot({ path: `${out}/search-resilience_scan_${tag}.png` });
      await click('[data-act="scan-dorks-retry"]');
      await wait(500);
      const sn = await text("#snack");
      ok(`${lang}: retry snack`, sn.length > 0 && (lang !== "en" || !cyr(sn)), sn);
      ok(`${lang}: banner gone after the retry`, !(await ev(() => !!document.querySelector(".scn-dorks"))));
      const p = await ev(() => FOCA.api.dorks_pending());
      ok(`${lang}: nothing pending`, p.pending === 0, p);
      await ev(() => FOCA.api.scan_stop("user"));
      await wait(400);
    }
    await ev(() => FOCA.i18n.setLang("ru"));
  } catch (e) {
    ok("exception", false, String(e && e.stack ? e.stack : e));
  }
  const lines = log.map(([s, n, d]) => `${s.padEnd(4)} ${n}${s === "FAIL" ? "  " + JSON.stringify(d) : ""}`);
  lines.push(`${log.length - fails} OK, ${fails} FAIL`);
  fs.writeFileSync(`${out}/search-resilience_${tag}.txt`, lines.join("\n") + "\n");
  console.log(lines.join("\n"));
};
