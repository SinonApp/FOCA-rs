// Consistency audit across all routes: headers, button/icon/heading sizes.
import fs from 'fs';
export default async (page, { out }) => {
  const routes = fs.readFileSync(new URL('../../routes.txt', import.meta.url), 'utf8').trim().split(',');
  const res = [];
  for (const r of routes) {
    await page.evaluate(r => { FOCA.reset(['/p/overview', r], 'none'); }, r);
    await page.waitForTimeout(120);
    res.push(await page.evaluate(r => {
      const $ = s => document.querySelector(s), pg = document.querySelector('.page');
      const vis = e => { const b = e.getBoundingClientRect(); return b.width > 0 && b.height > 0; };
      const all = s => [...pg.querySelectorAll(s)].filter(vis);
      const px = v => Math.round(parseFloat(v));
      const uniq = a => [...new Set(a)].sort((x, y) => (x > y ? 1 : -1));
      const btnSmall = all('.btn').filter(b => b.getBoundingClientRect().height < 47.5 && !b.classList.contains('sm') && !b.classList.contains('text')).map(b => (b.className + ':' + Math.round(b.getBoundingClientRect().height) + ':' + b.textContent.trim().slice(0, 18)));
      const ibSmall = all('button.ib').filter(b => b.getBoundingClientRect().height < 43.5).map(b => b.className + ':' + Math.round(b.getBoundingClientRect().height));
      const tap = all('button, [data-act]').filter(b => { const q = b.getBoundingClientRect(); return q.height < 36 && !b.closest('svg') && b.tagName !== 'svg' && getComputedStyle(b).display !== 'inline'; }).map(b => b.tagName + '.' + (b.className.baseVal ?? b.className).slice(0, 30) + ':' + Math.round(b.getBoundingClientRect().height));
      const h2 = uniq(all('h2, h3, .sec-h h2, .sub-h').map(e => e.tagName + '.' + (e.className || '') + '=' + getComputedStyle(e).fontSize));
      const lead = uniq(all('.lead-ic').map(e => Math.round(e.getBoundingClientRect().width)));
      const pills = uniq(all('.pill').map(e => getComputedStyle(e).fontSize));
      const lists0 = all('.list').filter(e => e.getBoundingClientRect().width < 120).length;
      const cs = getComputedStyle(pg);
      return { r, t: $('#tb-t').textContent, s: $('#tb-s').hidden ? '' : $('#tb-s').textContent, back: !$('#tb-back').hidden, nav: $('#nav').classList.contains('show'), tab: ($('#nav button.on span') || {}).textContent || '', pad: [cs.paddingTop, cs.paddingLeft].map(px).join('/'), btnSmall: btnSmall.slice(0, 6), ibSmall: ibSmall.slice(0, 4), tap: tap.slice(0, 6), h2, lead, pills, lists0 };
    }, r));
  }
  fs.writeFileSync(out + '/audit.json', JSON.stringify(res, null, 1));
};
