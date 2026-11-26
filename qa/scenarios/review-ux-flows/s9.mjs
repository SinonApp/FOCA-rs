// Audit of tap targets (<44px), buttons without an accessible name, and a Back dead end after a deep link.
export default async (page, ctx) => { const log = []; try { await run(page, ctx, log); } catch (e) { log.push({ ERR: String(e).slice(0, 400) }); } finally { console.error('L2LOG ' + JSON.stringify(log)); } };
const run = async (page, { out, W, prep }, log) => {
  const open = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(350); };
  for (const r of ['/p/scan', '/p/scan-stopped/vpn', '/new', '/p/finding/4', '/p/report-new', '/settings/keys']) {
    await open(r);
    const st = await page.evaluate(() => ({ back: !document.querySelector('#tb-back').hidden, nav: document.querySelector('#nav').classList.contains('show') }));
    await page.evaluate(() => FOCA.back()); await page.waitForTimeout(250);
    log.push({ deeplink: r, ...st, routeAfterBack: await page.evaluate(() => FOCA.current()) });
  }
  const routes = ['/projects', '/new', '/p/overview', '/p/findings', '/p/finding/4', '/p/data/docs', '/p/data/people', '/p/doc/1', '/p/entity/person/a.bondar', '/p/reports', '/p/report-new', '/p/search', '/p/scan', '/settings/network', '/settings/keys', '/p/scope', '/confirm-active'];
  for (const r of routes) {
    await open(r);
    const res = await page.evaluate(() => {
      const H = innerHeight;
      const els = [...document.querySelectorAll('button, a, [role=button], [role=tab], [role=radio], [role=checkbox], [role=switch], [data-act], input, select, textarea')].filter(e => { const b = e.getBoundingClientRect(); return b.width > 0 && b.height > 0 && getComputedStyle(e).visibility !== 'hidden'; });
      const small = []; const noname = [];
      const seen = new Set();
      for (const e of els) {
        const b = e.getBoundingClientRect();
        const name = (e.getAttribute('aria-label') || e.innerText || e.value || e.placeholder || e.title || '').trim();
        const key = (e.className && e.className.baseVal === undefined ? e.className : '') + '|' + name.slice(0, 20);
        if ((b.height < 44 || b.width < 44) && !seen.has(key)) { seen.add(key); small.push(`${e.tagName.toLowerCase()}.${String(e.className).split(' ')[0]} «${name.slice(0, 22)}» ${Math.round(b.width)}x${Math.round(b.height)}`); }
        if (!name && ['BUTTON', 'A'].includes(e.tagName)) noname.push(`${e.tagName.toLowerCase()}.${String(e.className).split(' ')[0]} ${e.dataset.act || ''}`);
      }
      return { small: small.slice(0, 12), nSmall: small.length, noname: noname.slice(0, 6) };
    });
    log.push({ r, ...res });
  }
};
