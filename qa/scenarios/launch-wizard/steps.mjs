// Launch wizard steps: sheets, the advanced section, the custom profile, confirmation.
export default async (page, { out, W, prep }) => {
  const sfx = await page.evaluate(() => `${innerWidth}_fs${getComputedStyle(document.documentElement).getPropertyValue('--fs').trim()}_${document.documentElement.dataset.theme}`);
  const shot = async n => { await page.waitForTimeout(400); const ov = await page.evaluate(() => { const els = [...document.querySelectorAll('.page, .sheet .sh-b')]; return els.map(e => e.scrollWidth - e.clientWidth); }); console.error('STEP', n, 'overflow', JSON.stringify(ov)); await page.screenshot({ path: `${out}/step_${n}_${sfx}.png` }); };
  const go = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };
  // Projects: actions sheet and deletion.
  await go('/projects');
  await page.evaluate(() => FOCA.actions['pj-menu']('logistics')); await shot('pj_menu');
  await page.evaluate(() => FOCA.actions['pj-del']('logistics')); await shot('pj_del');
  // /new: custom profile + advanced section.
  await go('/new');
  await page.evaluate(() => { FOCA.actions['la-prof']('custom'); FOCA.actions['la-adv'](); });
  await page.evaluate(() => { const p = FOCA.page(); p.scrollTop = p.querySelector('.la-mods').offsetTop - 80; }); await shot('new_custom');
  await page.evaluate(() => { const p = FOCA.page(); p.scrollTop = p.querySelector('.la-adv').offsetTop - 20; }); await shot('new_adv1');
  await page.evaluate(() => { const p = FOCA.page(); p.scrollTop = p.scrollHeight; }); await shot('new_adv2');
  await page.evaluate(() => FOCA.actions['la-files']()); await shot('new_files');
  await page.evaluate(() => FOCA.actions['la-import']()); await shot('new_import');
  // Scope: engagement parameters.
  await go('/p/scope');
  await page.evaluate(() => FOCA.actions['la-params']()); await shot('scope_edit');
  // "Full" starts with one tap on "start", without confirmation.
  await go('/new');
  await page.evaluate(() => { FOCA.actions['la-prof']('full'); const p = FOCA.page(); p.scrollTop = p.scrollHeight; }); await shot('full_ready');
  await page.evaluate(() => FOCA.actions['la-start']()); await page.waitForTimeout(300); await shot('after_start');
  // Empty project list.
  await go('/projects');
  await page.evaluate(() => { FOCA.projects.length = 0; FOCA.render(true); }); await shot('pj_empty');
  // /new without targets.
  await page.evaluate(() => { FOCA.state.newTarget = ''; FOCA.go('/new'); }); await shot('new_empty');
};
