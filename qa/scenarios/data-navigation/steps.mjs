// Data navigation: document paging, multi-select + Back, filters/sorting, secrets, relation links and breadcrumbs.
export default async (page, ctx) => { const log = []; try { await run(page, ctx, log); } finally { console.error(JSON.stringify(log)); } };
const run = async (page, { out, W, prep }, log) => {
  const shot = async n => { await page.waitForTimeout(350); await page.screenshot({ path: `${out}/step_${n}_${W}.png` }); };
  const ev = (f, a) => page.evaluate(f, a);
  const dump = async t => log.push({ t, r: await ev(() => [FOCA.current(), document.querySelectorAll('.dt-doc').length]) });
  const open = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };

  // 1) The Data tab via bottom navigation; switching segments does not grow the stack.
  await open('/p/overview');
  await page.click('#nav [data-tab="/p/data"]'); await page.waitForTimeout(300);
  await page.click('[data-act="dt-seg:people"]'); await page.waitForTimeout(250);
  await page.click('[data-act="dt-seg:hosts"]'); await page.waitForTimeout(250);
  log.push({ seg_route: await ev(() => FOCA.current()), back_visible: await ev(() => !document.querySelector('#tb-back').hidden) });
  await page.click('[data-act="dt-seg:docs"]'); await page.waitForTimeout(250);

  // 2) Loading more on scroll.
  log.push({ rows_before: await ev(() => document.querySelectorAll('.dt-doc').length) });
  await ev(() => document.querySelector('#dt-more').scrollIntoView({ block: 'end' }));
  await page.waitForTimeout(150); await shot('01_loading_more');
  await page.waitForTimeout(700);
  log.push({ rows_after: await ev(() => document.querySelectorAll('.dt-doc').length) });
  await ev(() => { FOCA.page().scrollTop = 0; });

  await dump('before3');
  // 3) Long press → multi-select.
  const box = async i => { await ev(i => document.querySelectorAll('.dt-doc')[i].scrollIntoView({ block: 'center' }), i); await page.waitForTimeout(120); return page.locator('.dt-doc').nth(i).boundingBox(); };
  let b = await box(1);
  await page.mouse.move(b.x + 120, b.y + 20); await page.mouse.down(); await page.waitForTimeout(650); await page.mouse.up(); await page.waitForTimeout(250);
  await page.locator('.dt-doc').nth(2).click(); await page.locator('.dt-doc').nth(4).click();
  await ev(() => { FOCA.page().scrollTop = 0; });
  await shot('02_select_mode');
  log.push({ sel: await ev(() => FOCA.state.dataDocs.sel && FOCA.state.dataDocs.sel.size) });
  await page.goBack(); await page.waitForTimeout(400);
  log.push({ after_back: await ev(() => ({ sel: !!FOCA.state.dataDocs.sel, route: FOCA.current(), nav: getComputedStyle(document.querySelector('#nav')).display })) });
  // Delete with undo.
  b = await box(0);
  await page.mouse.move(b.x + 120, b.y + 20); await page.mouse.down(); await page.waitForTimeout(650); await page.mouse.up(); await page.waitForTimeout(250);
  await page.click('[data-act="dd-bulk:del"]'); await page.waitForTimeout(300);
  log.push({ after_del: await ev(() => FOCA.dataDocs.count()) });
  await shot('03_deleted_snack');
  await page.click('#snack .sn-a'); await page.waitForTimeout(300);
  log.push({ after_undo: await ev(() => FOCA.dataDocs.count()) });

  // 4) Sorting and filters.
  await page.click('.dt-sortb'); await shot('04_sort_sheet');
  await page.click('[data-act="dd-sort:findings"]'); await page.waitForTimeout(300);
  await page.click('[data-act="dd-filters"]'); await page.waitForTimeout(300);
  await page.locator('.sheet [data-g="ext"] .chip[data-v="docx"]').click();
  await page.locator('.sheet [data-g="year"] .chip[data-v="2024"]').click();
  await shot('05_filter_sheet');
  await page.click('#dd-apply'); await page.waitForTimeout(300);
  await shot('06_filtered');
  log.push({ filtered: await ev(() => FOCA.state.dataDocs.order.length) });
  // Document card from the filtered list → next.
  await page.locator('.dt-doc').nth(0).click(); await page.waitForTimeout(400);
  log.push({ doc_sub: await ev(() => document.querySelector('#tb-s').textContent) });
  await page.click('.dt-pn .btn:last-child'); await page.waitForTimeout(400);
  log.push({ doc_next: await ev(() => FOCA.current()) });
  await page.click('[data-act="dd-sha"]'); await page.waitForTimeout(200);
  await ev(() => document.querySelector('.dt-sha').scrollIntoView({ block: 'center' }));
  await shot('07_doc_sha_open');

  // 5) Relation links and breadcrumbs.
  await open('/p/doc/1');
  await page.click('.dt-kv .kvr.tap >> nth=0'); await page.waitForTimeout(400); // author → person
  await page.click('.dt-relg .row.tap >> nth=0'); await page.waitForTimeout(400); // related → software
  await page.click('.dt-relg .row.tap >> nth=0'); await page.waitForTimeout(400); // people of this software
  await shot('08_crumbs');
  log.push({ crumbs: await ev(() => [...document.querySelectorAll('.dt-crumb')].map(x => x.textContent.trim())) });
  await page.click('.dt-crumb >> nth=0'); await page.waitForTimeout(500);
  log.push({ after_crumb: await ev(() => FOCA.current()) });
  log.push({ crumbs_after: await ev(() => document.querySelectorAll('.dt-crumb').length) });

  // 6) Secrets: fingerprint and reveal.
  await open('/p/data/secrets');
  await page.click('[data-act="dt-sec-show:1"]'); await shot('09_finger_sheet');
  await page.click('[data-act="dt-finger-ok"]'); await page.waitForTimeout(300);
  await shot('10_secret_revealed');
  await page.click('[data-act="dt-sec-copy:1"]'); await page.waitForTimeout(200);
  log.push({ snack: await ev(() => document.querySelector('#snack').textContent) });

  // 7) "Search for this".
  await open('/p/entity/host/files.contoso.example');
  await page.click('[data-act^="dt-search:"]'); await page.waitForTimeout(400);
  log.push({ search: await ev(() => ({ r: FOCA.current(), q: document.querySelector('#gq') && document.querySelector('#gq').value })) });
  await shot('11_search');
};
