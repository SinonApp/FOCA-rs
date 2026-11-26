// Screenshots of key screens with the scan mini panel (scan paused), to check sticky panels.
export default async (page, { out, W, prep }) => {
  const fsc = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--fs').trim());
  await page.goto(new URL('../../../ui/index.html#/p/overview', import.meta.url).href); await page.waitForTimeout(300); await prep(); await page.waitForTimeout(200);
  await page.evaluate(async () => { await FOCA.actions['scan-start']({ profile: 'passive' }); });
  await page.waitForTimeout(300); await page.evaluate(() => document.querySelector('#mi-pp')?.click()); await page.waitForTimeout(300);
  const info = [];
  for (const [r, stack] of [['/p/finding/1', ['/projects', '/p/overview', '/p/findings', '/p/finding/1']], ['/p/findings', ['/projects', '/p/overview', '/p/findings']], ['/new', ['/projects', '/p/overview', '/new']], ['/confirm-active', ['/projects', '/p/overview', '/new', '/confirm-active']], ['/p/report-new', ['/projects', '/p/overview', '/p/reports', '/p/report-new']], ['/p/scan', ['/projects', '/p/overview', '/p/scan']], ['/p/data/docs', ['/projects', '/p/overview', '/p/data/docs']]]) {
    await page.evaluate(s => FOCA.reset(s), stack); await page.waitForTimeout(500);
    if (r === '/confirm-active') await page.evaluate(() => { FOCA.state.launch.profile = 'std'; FOCA.render(true); });
    await page.waitForTimeout(200);
    await page.screenshot({ path: `${out}/lay_${r.replace(/\W+/g, '_')}_${W}_fs${fsc}.png` });
    // Snackbar over a sticky panel: show it and check what is under the button centers.
    const sn = await page.evaluate(() => { FOCA.snack('Проверка снекбара', { action: () => {} }); return new Promise(res => setTimeout(() => { const hits = [...document.querySelectorAll('.page .foot .btn, #fab.show, #mini.show #mi-pp')].map(b => { const q = b.getBoundingClientRect(); if (!q.width) return null; const el = document.elementFromPoint(q.left + q.width / 2, q.top + q.height / 2); return { btn: (b.textContent.trim() || b.id).slice(0, 22), coveredBy: el && el.closest('#snack') ? 'SNACK' : 'ok' }; }).filter(Boolean); res(hits); }, 350)); });
    await page.screenshot({ path: `${out}/lay_${r.replace(/\W+/g, '_')}_${W}_fs${fsc}_snack.png` });
    await page.evaluate(() => document.querySelector('#snack').classList.remove('show'));
    info.push({ r, snack: sn });
  }
  console.log('LAY', JSON.stringify({ log: info }));
};
