// Scan screen logic checks and sheets.
const arg = k => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : null; };
const sfx = () => `${arg('w') || 393}_fs${arg('fs') || 1}_${arg('theme') || 'dark'}`;
export default async (page, { out, prep }) => {
  const open = async (r) => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(200); await prep(); await page.waitForTimeout(200); };
  const log = [];
  try {
  await open('/p/scan');
  log.push(['idle running', await page.evaluate(() => FOCA.scan.running)]);
  await page.click('[data-act="scan-quick"]'); await page.waitForTimeout(300);
  log.push(['started', await page.evaluate(() => [FOCA.scan.running, !!document.querySelector('#scn-run'), document.querySelector('#fab').dataset.act])]);
  // Scrolling does not jump during live updates.
  await page.evaluate(() => FOCA.scanDemo.ff(22));
  await page.evaluate(() => { const p = document.querySelector('.page'); p.scrollTop = 900; });
  const y0 = await page.evaluate(() => { const p = document.querySelector('.page'); const el = [...p.querySelectorAll('[data-anc]')].find(e => e.getBoundingClientRect().bottom > p.getBoundingClientRect().top + 1); return [p.scrollTop, el.id || el.className, el.getBoundingClientRect().top, el.dataset.fid]; });
  await page.waitForTimeout(400);
  const y1 = await page.evaluate((fid) => { const p = document.querySelector('.page'); const el = p.querySelector('[data-fid="' + fid + '"]'); return [p.scrollTop, el ? el.getBoundingClientRect().top : 'gone']; }, y0[3]);
  log.push(['scroll', y0, y1]);
  // Pause from the mini panel on the overview.
  await page.evaluate(() => FOCA.go('/p/overview')); await page.waitForTimeout(400);
  await page.click('#mi-pp'); await page.waitForTimeout(300);
  log.push(['mini paused', await page.evaluate(() => [FOCA.scan.paused, document.querySelector('#mi-t').textContent])]);
  await page.click('#mini .mi-txt'); await page.waitForTimeout(500);
  log.push(['scan screen after mini', await page.evaluate(() => [FOCA.cur.path, document.querySelector('#fab').dataset.act, !!document.querySelector('[data-act="scan-resume"]')])]);
  // The FAB stays hidden while the inline Pause/Stop row is on screen: resume from that row.
  await page.click('.page [data-act="scan-resume"]'); await page.waitForTimeout(1300);
  log.push(['resumed', await page.evaluate(() => [FOCA.scan.paused, document.querySelector('#fab').dataset.act])]);
  // Source without a key opens the key sheet.
  await page.evaluate(() => FOCA.actions['scan-key']('searx')); await page.waitForTimeout(400);
  log.push(['searx key sheet', await page.evaluate(() => !!document.querySelector('.sheet.show #st-kv'))]); await page.evaluate(() => FOCA.closeSheet()); await page.waitForTimeout(300);
  // Stop: sheet + hold (the core demo scan is short, so pause it first to keep it from finishing).
  await page.evaluate(() => FOCA.actions['scan-pause']()); await page.waitForTimeout(200);
  await page.click('[data-act="scan-stop"]'); await page.waitForTimeout(400);
  const hb = await page.$('.sheet [data-hold]'); const bb = await hb.boundingBox();
  await page.evaluate(() => document.querySelector('.sheet [data-hold]').dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }))); await page.waitForTimeout(1400); await page.waitForTimeout(600);
  log.push(['afterhold', await page.evaluate(() => [FOCA.cur.path, !!document.querySelector('.sheet.show'), document.querySelector('.sheet [data-hold]')?.className])]);
  log.push(['stopped', await page.evaluate(() => [FOCA.cur.path, FOCA.scan.running, FOCA.scan.stopped && FOCA.scan.stopped.reason, document.querySelector('#mini').classList.contains('show')])]);
  await page.click('.scn-acts [data-act="scan-continue"]'); await page.waitForTimeout(500);
  log.push(['continued', await page.evaluate(() => [FOCA.cur.path, FOCA.scan.running])]);
  // Completion.
  await page.evaluate(() => FOCA.scanDemo.ff(60)); await page.waitForTimeout(800);
  log.push(['finished', await page.evaluate(() => [FOCA.scan.running, FOCA.scan.progress, !!FOCA.scan.finished, document.querySelector('#snack').textContent, !!document.querySelector('#scn-fin')])]);
  await page.screenshot({ path: `${out}/finished_${sfx()}.png` });
  // History.
  await page.click('[data-act^="scan-history:contoso-s2"]'); await page.waitForTimeout(500);
  await page.screenshot({ path: `${out}/histsheet_${sfx()}.png` });
  // Out of scope: add.
  await open('/p/out-of-scope');
  const o1 = await page.evaluate(() => FOCA.db.oos.find(o => !o.blocked && o.decision === 'new').id), o6 = await page.evaluate(() => FOCA.db.oos.find(o => o.blocked).id);
  await page.click(`[data-act="oos-add:${o1}"]`); await page.waitForTimeout(500);
  await page.screenshot({ path: `${out}/oosadd_${sfx()}.png` });
  await page.evaluate(id => FOCA.actions['oos-add-go'](id), o1); await page.evaluate(id => FOCA.actions['oos-ignore'](id), o6); await page.waitForTimeout(300);
  log.push(['oos', await page.evaluate(() => [...document.querySelectorAll('.scn-seg button')].map(b => b.textContent))]);
  // Active mode: "full" starts immediately, without confirmations.
  await open('/p/scan');
  await page.evaluate(() => FOCA.actions['scan-start']({ profile: 'full', active: true, open: true })); await page.waitForTimeout(400);
  await page.screenshot({ path: `${out}/activesheet_${sfx()}.png` });
  log.push(['active', await page.evaluate(() => [FOCA.scan.active, document.querySelector('#activebar').classList.contains('show'), !!document.querySelector('#scn-act')])]);
  } finally { console.log(JSON.stringify(log)); }
};
