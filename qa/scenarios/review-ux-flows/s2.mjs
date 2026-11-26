// Finding triage → document → author → computer → back → next. s3: a person's documents + login wordlist.
export default async (page, ctx) => { const log = []; try { await run(page, ctx, log); } catch (e) { log.push({ ERR: String(e).slice(0, 400) }); } finally { console.error('L2LOG ' + JSON.stringify(log)); } };
const run = async (page, { out, W, prep }, log) => {
  let taps = 0;
  const shot = async n => { await page.waitForTimeout(400); await page.screenshot({ path: `${out}/s2_${n}.png` }); };
  const cur = () => page.evaluate(() => FOCA.current());
  const tap = async (sel, note) => { const l = page.locator(sel).first(); await l.scrollIntoViewIfNeeded({ timeout: 4000 }); const b = await l.boundingBox(); await l.click({ timeout: 4000 }); taps++; await page.waitForTimeout(380); log.push({ taps, note, y: b && Math.round(b.y + b.height / 2), h: b && Math.round(b.height), route: await cur() }); };
  const back = async note => { await page.goBack(); taps++; await page.waitForTimeout(400); log.push({ taps, note: 'BACK ' + (note || ''), route: await cur() }); };
  const open = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };
  // Flow 2.
  await open('/projects');
  await tap('[data-pj="contoso"] .pj-name', 'project');
  await tap('#nav [data-tab="/p/findings"]', 'Findings tab');
  await shot('01_findings');
  const firstCrit = await page.evaluate(() => [...document.querySelectorAll('.fd-sw')].slice(0, 4).map(s => ({ id: s.dataset.id, t: s.querySelector('.fd-t').textContent })));
  log.push({ firstCards: firstCrit });
  // Open a finding with a source document (id 4: password in a document) by tapping its card.
  await tap('.fd-sw[data-id="4"] .fd-card', 'critical finding "Пароль в документе"');
  log.push({ sub: await page.evaluate(() => document.querySelector('#tb-s').textContent) });
  await shot('02_detail');
  const q = await page.locator('.fd-quick .btn').first().boundingBox(); log.push({ quickConfirmY: q && Math.round(q.y) });
  await tap('[data-act="fd-set:4:confirmed"]', 'Confirm');
  await shot('03_confirmed');
  await tap('.fd-srcdoc .row', 'source document');
  await shot('04_doc');
  await tap('.dt-kv .kvr.tap >> nth=0', 'Author');
  await shot('05_person');
  await tap('.dt-ehead ~ .list .row, h2:has-text("Компьютер") >> xpath=../following-sibling::div[1]//div[contains(@class,"row")]', "author's PC");
  await shot('06_pc');
  log.push({ crumbs: await page.evaluate(() => [...document.querySelectorAll('.dt-crumb')].map(c => c.textContent.trim())) });
  await back('to person'); await back('to document'); await back('to finding');
  await shot('07_back_to_finding');
  await tap('.fd-pn .btn:last-child', 'Next');
  log.push({ nextSub: await page.evaluate(() => document.querySelector('#tb-s').textContent), nextTitle: await page.evaluate(() => document.querySelector('.fd-h1') && document.querySelector('.fd-h1').textContent) });
  await back('from the next finding');
  log.push({ s2_total_taps: taps });
  // Flow 3.
  taps = 0;
  await open('/p/overview');
  await tap('#nav [data-tab="/p/data"]', 'Data tab');
  await tap('[data-act="dt-seg:people"]', 'People');
  await shot('10_people');
  await tap('.list .row.tap >> nth=0', 'first person');
  const who = await cur(); log.push({ who });
  await tap('.dt-findby [data-act^="dt-docs-filter"]', 'Documents (filtered by author)');
  log.push({ docsRoute: await cur(), docsBar: await page.evaluate(() => document.querySelector('.dt-bar-n').textContent), filterChips: await page.evaluate(() => [...document.querySelectorAll('.dt-fchip')].map(c => c.textContent.trim())), actions: await page.evaluate(() => [...document.querySelectorAll('#tb-acts .ib')].map(b => b.getAttribute('aria-label'))), backVisible: await page.evaluate(() => !document.querySelector('#tb-back').hidden) });
  await shot('11_docs_by_author');
  // Look for the login export: the ⋮ menu.
  await tap('#tb-acts [data-act="menu"]', '⋮ menu');
  log.push({ menu: await page.evaluate(() => [...document.querySelectorAll('.sheet .srow .lbl')].map(x => x.firstChild.textContent)) });
  await back('close menu');
  // Path through E-mail → wordlist export.
  await tap('[data-act="dt-seg:emails"]', 'E-mail');
  await tap('[data-act="dt-mail-export"]', 'Wordlist export');
  await shot('12_export_emails_step1');
  await tap('[data-act="rp-ex-fmt:dict"]', 'Wordlist .txt');
  log.push({ dictChipOn: await page.evaluate(() => document.querySelector('.rp-radio .chip.on') && document.querySelector('.rp-radio .chip.on').textContent), sheetTitle: await page.evaluate(() => document.querySelector('.sheet .sh-h h3').textContent) });
  await shot('13_export_dict');
  await back('close sheet');
  // Path through Reports → Wordlists.
  await tap('#nav [data-tab="/p/reports"]', 'Reports tab');
  await tap('[data-act="rp-quick:dict"]', 'Wordlists');
  log.push({ dictChipOn2: await page.evaluate(() => document.querySelector('.rp-radio .chip.on') && document.querySelector('.rp-radio .chip.on').textContent) });
  await shot('14_reports_dict');
  await tap('[data-act="rp-ex-share"]', 'Share…');
  await shot('15_share');
  log.push({ s3_taps: taps });
};
