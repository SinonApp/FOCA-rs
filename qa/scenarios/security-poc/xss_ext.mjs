// PoC: the document extension (the part of the name after the last dot) reaches innerHTML without esc().
// Checks: (1) without CSP the payload executes; (2) with the app CSP from src-tauri/tauri.conf.json the
// inline handler is blocked, but the <img> element is still injected into the DOM (HTML injection).
import { readFileSync } from 'node:fs';
export default async (page, o) => {
  const conf = JSON.parse(readFileSync(new URL('../../../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
  const csp = Object.entries(conf.app.security.csp).map(([k, v]) => `${k} ${v}`).join('; ').replace('ipc: http://ipc.localhost', "'self'");
  await page.addInitScript(() => { window.__xs = []; window.__x = n => { window.__xs.push(n); }; });
  const routes = ['/p/data/docs', '/p/doc/3', '/p/overview', '/p/search'];
  const run = async tag => {
    await o.go('/projects');
    await fetch(o.real + '/invoke', { method: 'POST', body: JSON.stringify({ cmd: 'project_open', args: { id: 'xss-passive' } }) });
    for (const r of routes) {
      await o.go(r); await page.waitForTimeout(600);
      const res = await page.evaluate(() => ({ exec: window.__xs.splice(0), injected: document.querySelectorAll('.page img[src="x"]').length }));
      console.log(`R1_EXT ${tag} ${r} exec=${JSON.stringify(res.exec)} injected_img=${res.injected}`);
    }
  };
  await run('no-csp');
  await page.route(u => u.pathname.endsWith('/index.html'), async route => {
    const resp = await route.fetch();
    const headers = { ...resp.headers() };
    if ((headers['content-type'] || '').includes('text/html')) headers['content-security-policy'] = csp;
    await route.fulfill({ response: resp, headers });
  });
  const viol = []; page.on('console', m => { if (/Content Security Policy/.test(m.text())) viol.push(m.text().slice(0, 140)); });
  await run('app-csp');
  console.log('R1_EXT csp-violations', viol.length, viol[0] || '');
};
