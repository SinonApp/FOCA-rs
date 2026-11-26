// Screenshots of routes at phone width plus checks (console errors, horizontal overflow,
// "undefined/NaN/null/[object Object]" in the page text).
// node qa/shoot.mjs --routes "/p/overview,/p/findings" --out $PWD/qa/out/<dir> --w 393 --fs 1 --theme dark [--steps steps.mjs] [--demo normal|empty|loading|error] [--tall]
//   [--real http://127.0.0.1:8787]  (or FOCA_REAL=…) uses the real core: `foca serve` + qa/tauri-shim.js (window.__TAURI__)
//   [--locale ru-RU]  device locale (the app's "auto" language follows it); scenarios are written for the Russian UI
// Demo mode: the help bundle and the UI dictionary come from locales/<lang>/, as the core serves them (the demo
// backend only has short stubs).
// Playwright: PW_CORE (path to playwright-core/index.js, set by qa/shoot.sh from qa/local.env) or the package from node_modules.
const { chromium } = (await import(process.env.PW_CORE || 'playwright-core')).default;
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { demoFindings } from './demo-locales.mjs';
const ROOT = fileURLToPath(new URL('..', import.meta.url)); // repository root
const arg = k => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : null; };
const has = k => process.argv.includes('--' + k);
const routes = (arg('routes') || '/p/overview').split(',').filter(x => x && x !== 'none');
const out = arg('out') || path.join(ROOT, 'qa/out/misc'); fs.mkdirSync(out, { recursive: true });
const W = +(arg('w') || 393), H = +(arg('h') || 852), fsc = +(arg('fs') || 1), theme = arg('theme') || 'dark', demo = arg('demo') || 'normal';
const real = (arg('real') || process.env.FOCA_REAL || '').replace(/\/$/, '');
const BASE = real ? real + '/index.html#' : new URL('../ui/index.html#', import.meta.url).href;
const b = await chromium.launch({ args: ['--disable-gpu', '--disable-dev-shm-usage'] });
const locale = arg('locale') || 'ru-RU';
const ctx = await b.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, locale });
if (real) await ctx.addInitScript({ path: path.join(ROOT, 'qa/tauri-shim.js') });
else {
  const help = {};
  for (const l of ['en', 'ru', 'uk']) help[l] = JSON.parse(fs.readFileSync(path.join(ROOT, 'locales', l, 'help.json'), 'utf8'));
  await ctx.addInitScript(h => { window.FOCA_DEMO_HELP = h; }, help);
  // The UI dictionary as the core merges it: ui.json plus locales/<lang>/ui/*.json.
  const ui = {};
  for (const l of ['en', 'ru', 'uk']) {
    ui[l] = JSON.parse(fs.readFileSync(path.join(ROOT, 'locales', l, 'ui.json'), 'utf8'));
    const dir = path.join(ROOT, 'locales', l, 'ui');
    if (fs.existsSync(dir)) for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort()) Object.assign(ui[l], JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
  }
  await ctx.addInitScript(u => { window.FOCA_DEMO_UI = u; }, ui);
  await ctx.addInitScript(f => { window.FOCA_DEMO_FINDINGS = f; }, demoFindings(ROOT));
}
const p = await ctx.newPage();
const errs = []; p.on('pageerror', e => errs.push(e.message)); p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
const prep = async () => { await p.evaluate(([fsc, theme, demo]) => { document.documentElement.style.setProperty('--fs', fsc); FOCA.setTheme(theme); if (demo !== 'normal') FOCA.setDemoMode(demo); window.__setInsets(32, 20, 0, 0); }, [fsc, theme, demo]); };
// Readiness: with the real core the first load is asynchronous, so wait for the router.
const ready = async () => { await p.waitForFunction(() => window.FOCA && FOCA.cur && document.querySelector('.page'), null, { timeout: 15000 }).catch(() => errs.push('READY timeout ' + p.url())); };
const BAD_TEXT = /\b(undefined|NaN|null|\[object Object\])\b/;
// The visible page, sheet and snackbar text must not contain undefined/NaN/null; otherwise fail with context.
const checkText = async (label) => {
  const hit = await p.evaluate((src) => {
    const re = new RegExp(src);
    const els = [document.querySelector('#app') || document.body];
    for (const el of els) { const t = el.innerText || ''; const m = t.match(re); if (m) { const i = m.index; return t.slice(Math.max(0, i - 60), i + 40).replace(/\s+/g, ' '); } }
    const attrs = [...document.querySelectorAll('[aria-label],[title],[placeholder]')].map(e => [e.getAttribute('aria-label'), e.getAttribute('title'), e.getAttribute('placeholder')].join(' ')).join(' | ');
    const m2 = attrs.match(re); return m2 ? 'attr: ' + attrs.slice(Math.max(0, m2.index - 60), m2.index + 40) : null;
  }, BAD_TEXT.source);
  if (hit) errs.push(`TEXT ${label}: …${hit}…`);
  return hit;
};
const go = async r => { await p.goto('about:blank'); await p.goto(BASE + r); await ready(); await p.waitForTimeout(real ? 400 : 250); await prep(); await p.waitForTimeout(350); };
const report = [];
for (const r of routes) {
  await go(r);
  const ov = await p.evaluate(() => { const pg = document.querySelector('.page'); const wide = [...document.querySelectorAll('.page *')].filter(e => e.getBoundingClientRect().right > innerWidth + 1).slice(0, 5).map(e => e.tagName + '.' + e.className); return { sw: pg ? pg.scrollWidth - pg.clientWidth : 0, docw: document.documentElement.scrollWidth - innerWidth, wide }; });
  await checkText(r);
  const name = r.replace(/[^\w]+/g, '_').replace(/^_|_$/g, '') || 'root';
  const file = `${out}/${name}_${W}_fs${fsc}_${theme}${demo !== 'normal' ? '_' + demo : ''}.png`;
  if (has('tall')) { const hgt = await p.evaluate(() => document.querySelector('.page').scrollHeight); await p.setViewportSize({ width: W, height: Math.min(4000, Math.max(H, hgt + 200)) }); await p.waitForTimeout(200); }
  await p.screenshot({ path: file });
  if (has('tall')) await p.setViewportSize({ width: W, height: H });
  report.push({ route: r, file: path.resolve(file).startsWith(ROOT) ? path.relative(ROOT, file) : file, overflow: ov });
}
const steps = arg('steps');
if (steps) { const mod = await import(steps); await mod.default(p, { out, W, fsc, theme, prep, real, base: BASE, go, ready, checkText, errs }); }
console.log(JSON.stringify({ errors: errs, report }, null, 1));
await b.close();
