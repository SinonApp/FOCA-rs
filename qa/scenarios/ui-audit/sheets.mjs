// Sheets: the ⋮ menu (F.menuItems), tools, filters, export, contract, scan stop; graph preview in #overlay-slot.
export default async (page, { out, W, prep }) => {
  const tag = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--fs').trim() + '_' + document.documentElement.dataset.theme);
  const shot = async n => { await page.waitForTimeout(380); await page.screenshot({ path: `${out}/sheet_${n}_${W}_fs${tag}.png` }); };
  const info = [];
  const go = async r => { await page.evaluate(r => FOCA.reset(['/p/overview', r], 'none'), r); await page.waitForTimeout(150); };
  const ov = () => page.evaluate(() => { const b = document.querySelector('.sheet .sh-b'); const f = document.querySelector('.sheet .sh-f'); return { sb: b ? b.scrollWidth - b.clientWidth : 0, sf: f ? f.scrollWidth - f.clientWidth : 0 }; });
  await go('/p/overview');
  await page.evaluate(() => FOCA.actions.menu()); await shot('menu');
  info.push({ menu: await page.evaluate(() => [...document.querySelectorAll('.sheet .srow .lbl')].map(x => x.firstChild.textContent)) });
  await page.evaluate(() => FOCA.actions['v2-tools']()); await shot('tools'); info.push({ tools: await ov() });
  await page.evaluate(() => FOCA.closeSheet());
  await go('/p/findings'); await page.evaluate(() => FOCA.actions['fd-filters']()); await shot('fd_filters'); info.push({ fd: await ov() });
  await page.evaluate(() => FOCA.closeSheet());
  await go('/p/data/docs'); await page.evaluate(() => FOCA.actions['dd-filters']()); await shot('dd_filters'); info.push({ dd: await ov() });
  await page.evaluate(() => FOCA.closeSheet());
  await go('/p/reports'); await page.evaluate(() => FOCA.exportSheet()); await shot('export'); info.push({ ex: await ov() });
  await page.evaluate(() => FOCA.closeSheet());
  await go('/p/scope'); await page.evaluate(() => FOCA.actions['la-contract']()); await shot('contract'); info.push({ contract: await ov() });
  await page.evaluate(() => FOCA.closeSheet());
  await go('/settings/keys'); await page.evaluate(() => FOCA.actions['st-key']('shodan')); await shot('key'); info.push({ key: await ov() });
  await page.evaluate(() => FOCA.closeSheet());
  // Graph preview in the slot and cleanup on navigation.
  await go('/p/graph/person/a.bondar');
  await page.evaluate(() => { const n = document.querySelector('.v2g-n.ctr'); FOCA.actions['v2g-tap'](n.dataset.k); });
  await shot('graph_peek');
  const inSlot = await page.evaluate(() => document.querySelectorAll('#overlay-slot .v2-peek').length);
  await page.evaluate(() => FOCA.back()); await page.waitForTimeout(300);
  const afterBack = await page.evaluate(() => ({ peek: document.querySelectorAll('.v2-peek').length, route: FOCA.current() }));
  await page.evaluate(() => { const n = document.querySelector('.v2g-n.ctr'); FOCA.actions['v2g-tap'](n.dataset.k); });
  await page.waitForTimeout(200);
  await page.evaluate(() => FOCA.go('/p/map')); await page.waitForTimeout(300);
  const afterLeave = await page.evaluate(() => ({ peek: document.querySelectorAll('.v2-peek').length, slot: document.getElementById('overlay-slot').children.length, route: FOCA.current() }));
  info.push({ inSlot, afterBack, afterLeave });
  console.error('SHEETS ' + JSON.stringify(info));
};
