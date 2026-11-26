// Accessible names in sheets and menus. On each route it taps one element per action
// (header buttons, FAB, page [data-act]) and, if a sheet/menu/confirmation opens, checks it for
// button / [data-act] / [role=…] / input without an accessible name (aria-label, title, text, placeholder, label[for]).
// Destructive and navigation actions are skipped. Run in parts (180 s limit):
// qa/shoot.sh --routes /p/overview --out qa/scenarios/regression-a11y --steps $PWD/qa/scenarios/regression-a11y/sheets.mjs --only "/p/findings,/p/finding/1"
import fs from 'fs';
export default async (page, { out, W, prep }) => {
  const i = process.argv.indexOf('--only');
  let routes = fs.readFileSync(new URL('../../routes.txt', import.meta.url), 'utf8').trim().split(',').concat(['/p/preflight']);
  if (i > 0) routes = process.argv[i + 1].split(',');
  const SKIP = /^(go|back|tab|toggle|toggle-check|chip|copy|theme|theme-menu|retry|mini-open|mini-pp|search|gopen|gset|scan-|st-t$|st-set|st-step|st-wipe|fd-set|fd-bulk|dd-bulk|fd-nav|dd-nav|fd-seg|fd-sev$|dt-seg|dt-nav|dt-crumb|dd-del|fd-note-del|fd-ph-del|fd-tag-del|fd-tag-filter|fd-rel|demo-reset|set-demo|set-offline|la-start|la-go|la-del|v2w-go|st-lk|st-pin|st-reveal|bio-close|fd-sel|dd-sel|fd-hint-off|fd-reset|dd-reset|fd-unf|dd-unf|dt-mailf|gchip|new-scan|v2t-year|st-go|st-android|dt-relmore|dd-sha|fd-restore|st-bdone|st-bopen|st-btest)/;
  const all = [];
  for (const r of routes) {
    const reset = async () => { await page.evaluate(r => { FOCA.closeSheet(); const up = FOCA.parentOf(r) || []; FOCA.reset(up.concat(r).filter((x, i, a) => a.indexOf(x) === i), 'none'); }, r); await page.waitForTimeout(250); };
    await reset();
    const acts = await page.evaluate(() => {
      const seen = new Set(), list = [];
      const els = [...document.querySelectorAll('#tb-acts [data-act], #fab.show, .page [data-act]')];
      for (const e of els) { const a = e.dataset.act || ''; const n = a.split(':')[0]; if (seen.has(n) || e.disabled || e.closest('[data-hold]')) continue; seen.add(n); list.push(a); }
      return list;
    });
    const opened = [];
    for (const a of acts) {
      if (SKIP.test(a)) continue;
      const res = await page.evaluate(a => new Promise(res => {
        const el = [...document.querySelectorAll('[data-act]')].find(e => e.dataset.act === a); if (!el) return res(null);
        const before = FOCA.current();
        try { el.click(); } catch (e) { return res({ a, err: String(e) }); }
        setTimeout(() => {
          const sh = document.querySelector('.sheet.show') || document.querySelector('.finger-ov, .lock.show');
          if (!sh) return res({ a, sheet: false, moved: FOCA.current() !== before });
          const vis = e => { const s = getComputedStyle(e); if (s.visibility === 'hidden' || s.display === 'none') return false; const q = e.getBoundingClientRect(); return q.width > 0 && q.height > 0 && !e.closest('[hidden],[aria-hidden="true"]'); };
          const name = e => (e.getAttribute('aria-label') || e.getAttribute('aria-labelledby') || e.getAttribute('title') || e.innerText || e.value || e.getAttribute('placeholder') || '').trim() || (e.id && document.querySelector(`label[for="${e.id}"]`)?.innerText.trim()) || '';
          const sel = 'button,[data-act],[role=button],[role=link],[role=tab],[role=radio],[role=checkbox],[role=switch],a[href],input,select,textarea,[data-hold]';
          const noname = [...sh.querySelectorAll(sel)].filter(vis).filter(e => !(e.parentElement && e.parentElement.closest('[data-act],button') && !e.matches('button,input,select,textarea,a[href]'))).filter(e => !name(e) && !(e.type === 'hidden')).map(e => e.outerHTML.slice(0, 120));
          const title = (sh.querySelector('.sh-h h3')?.textContent || sh.querySelector('h3,b')?.textContent || '').trim().slice(0, 40);
          res({ a, sheet: true, title, noname, dialog: sh.getAttribute('role') });
        }, 320);
      }), a);
      if (!res) continue;
      if (res.sheet) opened.push(res);
      await page.evaluate(() => { document.querySelectorAll('.finger-ov').forEach(x => x.remove()); FOCA.closeSheet(); });
      await page.waitForTimeout(120);
      if (res.moved || res.sheet) await reset();
    }
    all.push({ r, sheets: opened.length, opened: opened.map(o => o.a + ' «' + o.title + '»'), noname: opened.filter(o => o.noname.length).map(o => ({ a: o.a, title: o.title, noname: o.noname })) });
  }
  const tag = i > 0 ? process.argv[i + 1].replace(/\W+/g, '_').slice(0, 40) : 'all';
  fs.writeFileSync(`${out}/sheets_${W}_${tag}.json`, JSON.stringify(all, null, 1));
  console.log('SHEETS', JSON.stringify({ routes: all.length, sheets: all.reduce((s, x) => s + x.sheets, 0), noname: all.flatMap(x => x.noname.map(n => ({ r: x.r, ...n }))) }));
};
