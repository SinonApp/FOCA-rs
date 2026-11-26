// Measures the "chrome": how much screen height the fixed elements take
// (status bar + active mode bar + header + offline + sticky bottom .foot/.selbar + mini panel + search + navigation).
// The scan is started and paused (mini panel visible), as in qa/scenarios/review-ux-round2/lay.mjs. Threshold: 45% of the height.
// Run: qa/shoot.sh --routes /p/overview --out qa/scenarios/regression-a11y --w 360 --fs 2 --steps $PWD/qa/scenarios/regression-a11y/chrome.mjs [--only "/a,/b"]
import fs from 'fs';
export default async (page, { out, W, prep }) => {
  const i = process.argv.indexOf('--only');
  let routes = fs.readFileSync(new URL('../../routes.txt', import.meta.url), 'utf8').trim().split(',').concat(['/p/preflight']);
  if (i > 0) routes = process.argv[i + 1].split(',');
  const fsc = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--fs').trim());
  await page.goto(new URL('../../../ui/index.html#/p/overview', import.meta.url).href); await page.waitForTimeout(300); await prep(); await page.waitForTimeout(200);
  await page.evaluate(async () => { await FOCA.actions['scan-start']({ profile: 'passive' }); });
  await page.waitForTimeout(300); await page.evaluate(() => document.querySelector('#mi-pp')?.click()); await page.waitForTimeout(300);
  const res = [];
  for (const r of routes) {
    await page.evaluate(r => { const up = FOCA.parentOf(r) || []; FOCA.reset(up.concat(r).filter((x, i, a) => a.indexOf(x) === i), 'none'); }, r);
    await page.waitForTimeout(350);
    const m = await page.evaluate(() => {
      const H = innerHeight, parts = [];
      const add = (el, name) => { if (!el) return; const cs = getComputedStyle(el); if (cs.display === 'none' || cs.visibility === 'hidden') return; const q = el.getBoundingClientRect(); if (q.height < 1 || q.bottom <= 0 || q.top >= H) return; parts.push({ name, top: Math.max(0, Math.round(q.top)), bottom: Math.min(H, Math.round(q.bottom)) }); };
      add(document.querySelector('.statusfill'), 'status'); add(document.querySelector('#activebar'), 'activebar'); add(document.querySelector('.topbar'), 'topbar'); add(document.querySelector('#offline'), 'offline');
      add(document.querySelector('#bioind'), 'bioind');
      add(document.querySelector('#mini'), 'mini'); add(document.querySelector('#searchpill'), 'search'); add(document.querySelector('#nav'), 'nav'); add(document.querySelector('#navpad'), 'navpad');
      const pg = FOCA.page();
      // A sticky bottom counts only if it is pinned to the bottom of the visible page area.
      if (pg) { const pb = pg.getBoundingClientRect().bottom; pg.querySelectorAll('.foot, .selbar').forEach(f => { const q = f.getBoundingClientRect(); if (Math.abs(q.bottom - pb) < 3 || getComputedStyle(f).position === 'fixed') add(f, f.className.split(' ').slice(0, 2).join('.')); }); }
      parts.sort((a, b) => a.top - b.top); let used = 0, end = -1;
      for (const p of parts) { const s = Math.max(p.top, end); if (p.bottom > s) { used += p.bottom - s; end = Math.max(end, p.bottom); } }
      return { cur: FOCA.current(), H, used, pct: Math.round(used / H * 100), parts: parts.map(p => `${p.name}:${p.bottom - p.top}`).join(' ') };
    });
    res.push({ r, ...m, bad: m.pct > 45 });
  }
  const bad = res.filter(x => x.bad);
  fs.writeFileSync(`${out}/chrome_${W}_fs${fsc}.json`, JSON.stringify(res, null, 1));
  console.log('CHROME', JSON.stringify({ W, fs: fsc, max: Math.max(...res.map(x => x.pct)), bad: bad.map(x => `${x.r} ${x.pct}% [${x.parts}]`), top5: res.slice().sort((a, b) => b.pct - a.pct).slice(0, 6).map(x => `${x.r} ${x.pct}% [${x.parts}]`) }));
};
