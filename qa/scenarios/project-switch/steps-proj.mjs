// Project switch, empty project, search, demo data reset.
export default async (page, { out, W, prep }) => {
  const log = [];
  const shot = async n => { await page.waitForTimeout(350); await page.screenshot({ path: `${out}/sp_${n}_${W}.png` }); };
  const go = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };
  await go('/projects');
  await page.click('[data-act="pj-open:logistics"]'); await page.waitForTimeout(500);
  log.push(['kyiv', await page.evaluate(() => ({ route: FOCA.current(), sub: document.querySelector('#tb-s').textContent, docs: FOCA.sel.counts().docs.total, risk: FOCA.sel.risk().score, scope: FOCA.state.scope.num }))]);
  await shot('kyiv_overview');
  await page.evaluate(() => FOCA.tab('/p/findings')); await shot('kyiv_findings');
  await page.evaluate(() => FOCA.go('/p/data/people')); await shot('kyiv_people');
  // Reload: the project is remembered.
  await go('/p/overview');
  log.push(['reload_keeps', await page.evaluate(() => FOCA.project.id)]);
  // Empty project.
  await page.evaluate(() => FOCA.api.project_open('dnipro')); await page.waitForTimeout(400);
  await page.evaluate(() => FOCA.reset(['/projects', '/p/overview'])); await shot('dnipro_overview');
  for (const r of ['/p/findings', '/p/data/docs', '/p/timeline', '/p/diff', '/p/map', '/p/monitor', '/p/reports', '/p/scope', '/p/scan']) { await page.evaluate(r => FOCA.go(r), r); await page.waitForTimeout(250); }
  await shot('dnipro_scan');
  // "Full" starts without confirmations: start it and stop it.
  log.push(['active_started', await page.evaluate(() => FOCA.api.scan_start({ profile: 'full', active: true }).then(() => 'started', e => e.code))]);
  await page.evaluate(() => FOCA.api.scan_stop('user')); await page.waitForTimeout(300);
  // New project + backend demo scan.
  const id = await page.evaluate(() => FOCA.api.project_create({ name: 'newcorp.ua', client: 'ТОВ «Нью Корп»', targets: ['newcorp.ua'], excludes: [] }).then(p => p.id));
  await page.evaluate(id => FOCA.api.project_open(id).then(() => FOCA.reset(['/projects', '/p/overview'])), id);
  await page.evaluate(() => FOCA.api.scan_start({ profile: 'std' })); await page.waitForTimeout(3500); await shot('newcorp_mid');
  await page.waitForTimeout(4500);
  log.push(['newcorp', await page.evaluate(() => ({ docs: FOCA.sel.counts().docs.total, scans: FOCA.db.scans.length, people: FOCA.sel.counts().people.total }))]);
  await shot('newcorp_done');
  // Search by e-mail and findings.
  await page.evaluate(() => FOCA.api.project_open('contoso')); await page.evaluate(() => FOCA.go('/p/search')); await page.waitForTimeout(300);
  await page.fill('#gq', 'AWS'); await page.waitForTimeout(200);
  log.push(['search_aws', await page.evaluate(() => document.querySelectorAll('#gres .row').length)]);
  await page.fill('#gq', 'info@'); await page.waitForTimeout(200); await shot('search_mail');
  // Demo data reset.
  await page.evaluate(() => FOCA.actions['demo-reset']()); await page.waitForTimeout(500);
  log.push(['after_reset', await page.evaluate(() => ({ route: FOCA.current(), n: FOCA.projects.length, ids: FOCA.projects.map(p => p.id).join(',') }))]);
  console.error(JSON.stringify(log));
};
