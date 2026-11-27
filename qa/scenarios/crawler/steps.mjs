// Demo: crawler v2. Scan screen crawler card (pages, queue, documents, storage files, slowed by 429),
// the wizard's crawl limits and external storage toggle, Settings → Site crawl, document provenance
// (linked from a page, found in a document, Google export), the scope rule and the help article.
// bash qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/crawler/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/crawler_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const noOvf = async n => ok(`${n}: no horizontal overflow`, (await overflow()) <= 1, await overflow());
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    const em = await ev(() => /\u2014/.test(document.body.innerText));
    ok("no em dash on the first screen", !em);
    // Wizard: crawl limits, storage toggle, the run carries them to scan_start.
    await go("/new");
    await ev(() => { FOCA.actions["la-prof"]("custom"); if (!document.querySelector(".la-adv.open")) FOCA.actions["la-adv"](); }); await wait(350);
    let t = await txt();
    ok('wizard: "Обход сайта" with limits and storage toggle', /Обход сайта/.test(t) && /Страниц за скан/.test(t) && /Время обхода/.test(t) && /внешних хранилищах/.test(t), t.slice(0, 300));
    ok("wizard: depth 5 by default", await ev(() => (document.getElementById("nf-la-depth") || {}).value === "5"), await ev(() => (document.getElementById("nf-la-depth") || {}).value));
    await ev(() => { const r = document.getElementById("nf-la-depth"); if (r) r.scrollIntoView({ block: "center" }); });
    // no hard cap: 50 000 pages is accepted with a warning
    await ev(() => { const i = document.getElementById("nf-la-crawlPages"); i.focus(); i.value = "50000"; i.blur(); });
    await wait(200);
    ok("wizard: 50 000 pages warns, not capped", await ev(() => !document.getElementById("nf-la-crawlPages-w").hidden && /20 000|20000/.test(document.getElementById("nf-la-crawlPages-w").textContent)), await ev(() => document.getElementById("nf-la-crawlPages-w").textContent));
    await shot("launch"); await noOvf("wizard");
    // Scan: crawler counters, slowed by 429, rest continues in the next scan.
    await ev(() => FOCA.actions["scan-start"]({ profile: "std", open: true, crawl: { max_pages: 1000 } })); await wait(300);
    let c = null;
    for (let i = 0; i < 120 && !(c && c.stop); i++) { await wait(100); c = await ev(() => FOCA.scan.crawl); }
    await ev(() => FOCA.api.scan_pause()); await wait(200);
    ok("scan: crawl counters arrive (pages, storage)", c && c.pages >= 1000 && c.storage > 0, c);
    ok("scan: rate slowed by 429", c && c.rate === "slowed", c && c.rate);
    await go("/p/scan");
    t = await txt();
    ok('scan screen: "Обход сайта" card with pages and storage', /Обход сайта/.test(t) && /страниц/.test(t) && /в хранилищах/.test(t), t.slice(0, 500));
    ok("scan screen: slowed pill and the rest note", /темп снижен/.test(t) && /продолжится в следующем скане/.test(t));
    await ev(() => { const r = document.getElementById("scn-crawl"); if (r) r.scrollIntoView({ block: "center" }); });
    await shot("scan"); await noOvf("scan");
    await ev(() => FOCA.api.scan_stop()); await wait(300);
    // Passive profile: no crawl counters.
    await ev(() => FOCA.actions["scan-start"]({ profile: "passive", open: true })); await wait(300);
    await wait(1500);
    ok("passive scan: no crawl", !(await ev(() => FOCA.scan.crawl)));
    await ev(() => FOCA.api.scan_stop()); await wait(300);
    // Documents: provenance in the list and the card.
    await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    const prov = await ev(() => (FOCA.db.docs || []).filter(d => d.provenance).map(d => [d.id, d.provenance.kind, d.provenance.storage || "", !!d.provenance.export]));
    ok("demo: provenance kinds page, doc, storage, export", prov.some(p => p[1] === "page") && prov.some(p => p[1] === "doc") && prov.some(p => p[2] === "gdrive") && prov.some(p => p[3]), prov);
    const docId = (prov.find(p => p[1] === "doc") || [])[0];
    await go(`/p/doc/${docId}`);
    t = await txt();
    ok('doc card: "Найден в документе"', /Найден в документе/.test(t), t.slice(0, 400));
    await shot("doc_card"); await noOvf("doc card");
    const expId = (prov.find(p => p[3]) || [])[0];
    await go(`/p/doc/${expId}`);
    t = await txt();
    ok("doc card: Google export note", /Google/.test(t) && /экспорт/i.test(t), t.slice(0, 400));
    await go("/p/docs");
    t = await txt();
    ok("docs list: provenance short labels", /со страницы|из документа|Google Drive|Google Docs/.test(t), t.slice(0, 300));
    await noOvf("docs");
    // Scope: rule "linked external storage".
    await go("/p/scope");
    t = await txt();
    ok('scope: "Связанные внешние хранилища" rule', /Связанные внешние хранилища/.test(t), t.slice(-400));
    await noOvf("scope");
    // Settings → Site crawl.
    await go("/settings");
    t = await txt();
    ok('settings: "Обход сайта" entry', /Обход сайта/.test(t));
    await go("/settings/crawl");
    t = await txt();
    ok("crawl settings: limits, storage, images, document links", /Глубина/.test(t) && /Страниц за скан/.test(t) && /Фотографии для EXIF/.test(t) && /Ссылки внутри документов/.test(t), t.slice(0, 300));
    await ev(() => document.querySelector('[data-act="cr-t:storage:1"]').click()); await wait(250);
    ok("crawl settings: storage toggle saved off", await ev(() => FOCA.db.settings.crawl.storage === false));
    await ev(() => document.querySelector('[data-act="cr-t:storage:1"]').click()); await wait(250);
    await shot("settings"); await noOvf("settings");
    // Help article.
    await go("/help/crawler");
    t = await txt();
    ok('help: "Обход сайта" article with storage and 429', /Обход сайта/.test(t) && /Google Drive/.test(t) && /429/.test(t));
    await noOvf("help");
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/crawler_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
