// Captures real HTML fixtures from Startpage and Brave Search (same script as RenderFetcher.kt).
// node qa/search-fixtures.mjs <outdir> <domain> <ext> [pages]
// Run only under flock: flock -w 600 /tmp/foca-pw.lock node qa/search-fixtures.mjs …
import fs from 'fs';
// PW_CORE is the path to playwright-core/index.js (see qa/local.env.example); otherwise the package from node_modules.
const { chromium } = (await import(process.env.PW_CORE || 'playwright-core')).default;
const [out = '/tmp/search-fx', dom = 'nasa.gov', ext = 'pdf', pagesArg = '2', only = 'sp,brave'] = process.argv.slice(2);
const PAGES = +pagesArg;
fs.mkdirSync(out, { recursive: true });
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36';
const b = await chromium.launch({ args: ['--disable-blink-features=AutomationControlled'] });
const ctx = await b.newContext({ userAgent: UA, locale: 'en-US', viewport: { width: 1280, height: 2400 } });
await ctx.addInitScript(() => Object.defineProperty(navigator, 'webdriver', { get: () => undefined }));
const p = await ctx.newPage();
const Q = `site:${dom} filetype:${ext}`;
const tag = `${dom.replace(/\W/g, '_')}_${ext}`;
const save = async (name) => { const h = await p.evaluate(() => document.documentElement.outerHTML); fs.writeFileSync(`${out}/${name}.html`, h); console.log('saved', name, h.length, p.url()); return h; };
const waitGone = async (txt, maxS) => { for (let i = 0; i < maxS; i += 1) { const t = await p.evaluate(() => (document.readyState === 'complete' && document.body) ? document.body.innerText : 'Verifying your request').catch(() => txt); if (!t.includes(txt)) return i; await p.waitForTimeout(1000); } return -1; };
const res = {};
if (only.includes('sp')) {
  const t0 = Date.now();
  await p.goto('https://www.startpage.com/', { waitUntil: 'domcontentloaded' });
  const v0 = await p.evaluate(() => document.body?.innerText || '');
  if (v0.includes('Verifying your request')) await save(`startpage_verify`);
  console.log('sp home verify', await waitGone('Verifying your request', 60), 's');
  await p.evaluate(q => { const f = [...document.forms].find(f => /search/.test(f.action)); f.querySelector('[name=query]').value = q; f.submit(); }, Q);
  await p.waitForLoadState('domcontentloaded').catch(() => {});
  for (let pg = 1; pg <= PAGES; pg++) {
    const w = await waitGone('Verifying your request', 60); await p.waitForTimeout(1500);
    console.log('sp page', pg, 'verify', w);
    await save(`startpage_${tag}_p${pg}`);
    if (pg === PAGES) break;
    const ok = await p.evaluate(() => { const els = [...document.querySelectorAll('form button, form input[type=submit]')].filter(e => /next/i.test(e.innerText || e.value || e.getAttribute('aria-label') || '')); if (!els.length) return false; window.__foca = 1; els[0].form.submit(); return true; });
    if (!ok) { console.log('sp: no Next'); break; }
    await p.waitForTimeout(2500);
  }
  res.startpage_s = Math.round((Date.now() - t0) / 1000);
}
if (only.includes('brave')) {
  const t0 = Date.now();
  for (let pg = 1; pg <= PAGES; pg++) {
    const off = pg - 1;
    await p.goto(`https://search.brave.com/search?q=${encodeURIComponent(Q)}&source=web${off ? `&offset=${off}` : ''}`, { waitUntil: 'domcontentloaded' });
    await p.waitForTimeout(2500);
    await waitGone('Verifying', 30);
    await save(`brave_${tag}_p${pg}`);
    await p.waitForTimeout(4000);
  }
  res.brave_s = Math.round((Date.now() - t0) / 1000);
}
console.log(JSON.stringify(res));
await b.close();
