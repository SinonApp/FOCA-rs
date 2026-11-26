// Demo: standards references on the finding card and in the report builder after the 2025 refresh,
// ATT&CK v20 / OWASP Top 10:2025 tooltips, NIST SP 800-53 = НД ТЗІ 3.6-006-24 chips, GDPR / Law 2297-VI chips
// for personal data, the CWE Top 25 mark, the legacy note on НД ТЗІ 2.5-004-99 / 3.7-003-05, the help article
// in RU/UK/EN, no horizontal overflow.
// qa/shoot.sh --routes /p/overview --out $PWD/qa/out/std --w 393 --steps $PWD/qa/scenarios/standards-2025/steps.mjs
import fs from "fs";
export default async (page, { out, W }) => {
  const log = [];
  let fails = 0;
  const ok = (name, cond, data) => {
    if (!cond) fails++;
    log.push([cond ? "OK" : "FAIL", name, data]);
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => {
    await ev(r => FOCA.go(r), r);
    await wait(450);
  };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const fid = rule => ev(r => (FOCA.db.findings.find(f => f.provenance && f.provenance.rule === r) || {}).id, rule);
  const chips = () => ev(() => [...document.querySelectorAll(".fd-stdc")].map(x => [x.textContent, x.getAttribute("title")]));

  await ev(() => FOCA.api.project_open("contoso"));
  await wait(300);

  // Personal data finding: NIST/НД ТЗІ 3.6-006-24 and privacy chips, legacy note on КСЗІ.
  await go(`/p/finding/${await fid("pii")}`);
  let c = await chips();
  const txt = c.map(x => x[0]);
  ok("pii card: OWASP A01:2025 with the 2025 edition in the tooltip", c.some(([t, ti]) => t === "OWASP A01:2025" && /Top 10:2025/.test(ti)), c);
  ok("pii card: ATT&CK chip tooltip names v20", c.some(([t, ti]) => t === "ATT&CK T1213" && /ATT&CK v20/.test(ti)), c);
  ok("pii card: NIST AC-22 and SI-12(1) chips name НД ТЗІ 3.6-006-24", txt.includes("NIST AC-22") && txt.includes("NIST SI-12(1)") && c.every(([t, ti]) => !t.startsWith("NIST") || /3\.6-006-24/.test(ti)), c);
  ok("pii card: GDPR and Law 2297-VI chips", ["GDPR 5(1)(c)", "GDPR 5(1)(f)", "GDPR ст. 32", "2297-VI ст. 6", "2297-VI ст. 24"].every(x => txt.includes(x)), txt);
  ok("pii card: КСЗІ chip tooltip says it is for КСЗИ-certified systems", c.some(([t, ti]) => t === "КСЗІ 6.1.2.5" && /аттестованных по КСЗИ/.test(ti)), c);
  ok("pii card: no OWASP 2021 ids left", !txt.some(x => /:2021/.test(x)), txt);
  await page.screenshot({ path: `${out}/std_pii_${W}.png` });
  const v1 = await overflow();
  ok("pii card: no horizontal overflow", v1 <= 1, v1);

  // CWE Top 25 mark (CWE-22 path traversal).
  await go(`/p/finding/${await fid("zip.path_traversal")}`);
  c = await chips();
  ok("zip traversal: CWE-22 carries the Top 25 mark, SI-10 chip", c.some(([t, ti]) => t === "CWE-22 · Top 25" && /CWE Top 25 \(2025\)/.test(ti)) && c.some(([t]) => t === "NIST SI-10"), c);

  // Ukrainian and English chip labels.
  for (const [l, want, legacy] of [
    ["uk", "2297-VI ст. 24", /атестованих за КСЗІ/],
    ["en", "Law 2297-VI Art. 24", /certified under KSZI/],
  ]) {
    await ev(l => FOCA.i18n.setLang(l), l);
    await wait(500);
    await go(`/p/finding/${await fid("pii")}`);
    c = await chips();
    ok(`${l}: privacy chip and legacy tooltip translated`, c.some(([t]) => t === want) && c.some(([t, ti]) => legacy.test(ti || "")), c);
    await go("/help/standards");
    const h = await ev(() => (FOCA.page() || document.body).textContent);
    ok(`${l}: help article names ATT&CK v20, OWASP Top 10:2025 and НД ТЗІ 3.6-006-24`, /ATT&CK v20/.test(h) && /Top 10:2025/.test(h) && /3\.6-006-24/.test(h), h.slice(0, 200));
  }
  await ev(() => FOCA.i18n.setLang("ru"));
  await wait(400);
  await go("/help/standards");
  const h = await ev(() => (FOCA.page() || document.body).textContent);
  ok("ru: help article marks НД ТЗІ 2.5-004-99 / 3.7-003-05 as КСЗИ-only", /аттестованных по КСЗИ/.test(h) && /GDPR/.test(h), h.slice(0, 200));

  fs.writeFileSync(`${out}/std_log.json`, JSON.stringify(log, null, 1));
  for (const [s, n, d] of log) console.log(`  ${s.padEnd(4)} ${n}${s === "FAIL" ? " :: " + JSON.stringify(d).slice(0, 400) : ""}`);
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
