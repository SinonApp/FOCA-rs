// Based on qa/scenarios/review-ux-round2/a11y.mjs with extra checks: accessibility and layout on every route (buttons without a name, targets < 44×44, sticky panel overlaps).
import fs from 'fs';
export default async (page, { out, W, prep }) => {
  const routes = fs.readFileSync(new URL('../../routes.txt', import.meta.url), 'utf8').trim().split(',').concat(['/p/preflight']);
  const fsc = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--fs').trim());
  await page.goto(new URL('../../../ui/index.html#/p/overview', import.meta.url).href); await page.waitForTimeout(300); await prep(); await page.waitForTimeout(200);
  // Scan paused so the mini panel is visible.
  await page.evaluate(async () => { await FOCA.actions['scan-start']({ profile: 'passive' }); });
  await page.waitForTimeout(300);
  await page.evaluate(() => document.querySelector('#mi-pp')?.click());
  await page.waitForTimeout(300);
  const res = [];
  for (const r of routes) {
    await page.evaluate(r => { const pr = r.startsWith('/p/') && r !== '/p/overview' ? ['/projects', '/p/overview', r] : r.startsWith('/settings/') ? ['/projects', '/settings', r] : ['/projects', r]; if (r === '/projects') FOCA.reset(['/projects']); else FOCA.reset(pr); }, r);
    await page.waitForTimeout(450);
    const d = await page.evaluate(() => {
      const vis = e => { const s = getComputedStyle(e); if (s.visibility === 'hidden' || s.display === 'none' || +s.opacity === 0) return false; const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && !e.closest('[hidden],[aria-hidden="true"]') && !(e.closest('details:not([open])') && !e.closest('summary')); }; // contents of a collapsed <details> are not rendered
      const name = e => (e.getAttribute('aria-label') || e.getAttribute('aria-labelledby') || e.getAttribute('title') || e.innerText || e.value || e.getAttribute('placeholder') || '').trim();
      const labelFor = e => e.id && document.querySelector(`label[for="${e.id}"]`);
      const sel = 'button,[data-act],[role=button],[role=link],[role=tab],[role=radio],[role=checkbox],[role=switch],a[href],input,select,textarea,[data-tab],[data-hold]';
      const els = [...document.querySelectorAll(sel)].filter(e => !e.closest('#overlay-slot .sheet:not(.show)')).filter(vis);
      const noname = [], small = [];
      const desc = e => { const c = (typeof e.className === 'string' ? e.className : '').trim().split(/\s+/).slice(0, 2).join('.'); return `${e.tagName.toLowerCase()}${e.id ? '#' + e.id : ''}${c ? '.' + c : ''}${e.dataset.act ? '[' + e.dataset.act.slice(0, 28) + ']' : ''}`; };
      for (const e of els) {
        // A clickable nested in a clickable: count the outer one.
        if (e.parentElement && e.parentElement.closest('[data-act],button,[data-tab]') && !e.matches('button,input,select,textarea,a[href]')) continue;
        const nm = name(e) || (labelFor(e) && labelFor(e).innerText.trim());
        if (!nm && !(e.tagName === 'INPUT' && e.type === 'hidden')) noname.push(desc(e) + ' ' + (e.outerHTML.slice(0, 90)));
        const r = e.getBoundingClientRect();
        if (r.top > innerHeight || r.bottom < 0) {}
        let w = r.width, h = r.height;
        // Pseudo-elements that extend the hit area.
        for (const ps of ['::before', '::after']) { const s = getComputedStyle(e, ps); if (s.content !== 'none' && s.position === 'absolute') { const it = parseFloat(s.top), il = parseFloat(s.left); if (it < 0) h = Math.max(h, r.height - 2 * it); if (il < 0) w = Math.max(w, r.width - 2 * il); } }
        // A wrapping row (label/row) that holds a toggle or checkbox is clickable as a whole.
        const host = e.closest('label, .row.tap, .checkrow, .srow');
        if (host && host !== e) { const hr = host.getBoundingClientRect(); w = Math.max(w, hr.width); h = Math.max(h, hr.height); }
        if ((w < 44 || h < 44) && !e.matches('input[type=hidden],textarea') && !(e.tagName === 'A' && e.closest('p, .fd-text'))) small.push(`${desc(e)} «${(nm || '').replace(/\s+/g, ' ').slice(0, 24)}» ${Math.round(w)}×${Math.round(h)}`);
      }
      // Sticky/fixed bottom elements.
      const box = s => { const e = document.querySelector(s); if (!e || !vis(e)) return null; const r = e.getBoundingClientRect(); return { s, t: Math.round(r.top), b: Math.round(r.bottom), l: Math.round(r.left), r: Math.round(r.right) }; };
      const foots = [...document.querySelectorAll('.page .foot')].filter(vis).map(e => { const r = e.getBoundingClientRect(); return { s: '.foot', t: Math.round(r.top), b: Math.round(r.bottom), l: Math.round(r.left), r: Math.round(r.right), pos: getComputedStyle(e).position }; });
      const fixed = ['#mini', '#nav', '#fab', '#searchpill'].map(box).filter(Boolean).concat(foots);
      const over = [];
      for (let i = 0; i < fixed.length; i++) for (let j = i + 1; j < fixed.length; j++) { const a = fixed[i], b = fixed[j]; const ov = Math.min(a.b, b.b) - Math.max(a.t, b.t); const oh = Math.min(a.r, b.r) - Math.max(a.l, b.l); if (ov > 2 && oh > 2) over.push(`${a.s}∩${b.s} ${ov}px`); }
      const tb = document.querySelector('.topbar, header') ; const top = tb ? tb.getBoundingClientRect().bottom : 0;
      const bottom = Math.min(innerHeight, ...fixed.map(f => f.t));
      // Is the last page element reachable by scrolling (not hidden behind panels)?
      const pg = document.querySelector('.page'); let lastHidden = null;
      if (pg) { pg.scrollTop = pg.scrollHeight; const kids = [...pg.querySelectorAll('button,[data-act],.card,.row')].filter(vis).filter(e => !e.closest('.foot')); const last = kids[kids.length - 1]; if (last) { const lr = last.getBoundingClientRect(); const fl = fixed.filter(f => f.s !== '.foot' || true).filter(f => f.s !== '.foot'); const cover = Math.min(innerHeight, ...fl.map(f => f.t), ...foots.map(f => f.t)); if (lr.bottom > cover + 2) lastHidden = `${desc(last)} bottom ${Math.round(lr.bottom)} > ${Math.round(cover)}`; } pg.scrollTop = 0; }
      return { noname, small, fixed, over, contentH: Math.round(bottom - top), lastHidden, cur: FOCA.current() };
    });
    res.push({ r, ...d });
  }
  fs.writeFileSync(`${out}/a11y_${W}_fs${fsc}.json`, JSON.stringify(res, null, 1));
  // Every interactive element has a name; tap targets are ≥ 44×44; sticky panels do not overlap; the last element is reachable.
  const lines = [];
  const okL = (name, bad) => lines.push(`${bad.length ? 'FAIL' : 'OK'} ${name}${bad.length ? ' ' + JSON.stringify(bad.slice(0, 12)) : ''}`);
  okL(`D.1: accessible name on buttons and [data-act] (${res.length} routes, ${W}/fs${fsc})`, res.flatMap(x => x.noname.map(s => x.r + ' ' + s)));
  okL(`D.2/#22: tap targets ≥ 44×44 (${W}/fs${fsc})`, res.flatMap(x => x.small.map(s => x.r + ' ' + s)));
  okL(`N3/N8: sticky bars do not overlap (${W}/fs${fsc})`, res.filter(x => x.over.length).map(x => x.r + ' ' + x.over.join(';')));
  okL(`N8: last page element not hidden behind bars (${W}/fs${fsc})`, res.filter(x => x.lastHidden).map(x => x.r + ' ' + x.lastHidden));
  console.error(lines.join('\n'));
  console.error(`regression-round2 a11y: ${lines.filter(l => l.startsWith('OK')).length} OK, ${lines.filter(l => l.startsWith('FAIL')).length} FAIL`);
};
