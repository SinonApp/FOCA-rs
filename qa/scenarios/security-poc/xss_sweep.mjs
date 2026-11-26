// PoC: walks every UI route on the REAL core with a project whose document metadata contains
// <img src=x onerror=__x(N)>. window.__x(N) records that payload N EXECUTED in the WebView.
// qa/shoot.sh --real http://127.0.0.1:8897 --routes none --out /tmp/foca-e2e/shots --steps $PWD/qa/scenarios/security-poc/xss_sweep.mjs
import { readFileSync } from 'node:fs';
export default async (page, o) => {
  await page.addInitScript(() => { window.__xs = []; window.__x = n => { window.__xs.push([n, location.hash]); }; });
  const api = async (cmd, args = {}) => { const r = await fetch(o.real.replace(/\/$/, '') + '/invoke', { method: 'POST', body: JSON.stringify({ cmd, args }) }); const j = await r.json(); if (j.error) throw new Error(JSON.stringify(j.error)); return j.result; };
  await o.go('/projects');
  const pid = process.env.R1_PID || 'xss-passive';
  await api('project_open', { id: pid });
  const s = await api('project_snapshot', { id: pid });
  const docs = s.docs.filter(d => !d.deleted);
  const routes = readFileSync(new URL('../../routes.txt', import.meta.url), 'utf8').replace(/\n/g, ',').split(',').map(x => x.trim()).filter(Boolean);
  const extra = [...docs.map(d => '/p/doc/' + d.id), ...s.people.map(p => '/p/entity/person/' + encodeURIComponent(p.login)),
    ...s.people.map(p => '/p/graph/person/' + encodeURIComponent(p.login)), ...s.findings.map(f => '/p/finding/' + f.id),
    ...s.hosts.map(h => '/p/entity/host/' + encodeURIComponent(h.name)), ...(s.pcs || []).map(p => '/p/entity/pc/' + encodeURIComponent(p.name)),
    '/p/data/recon', '/p/data/tech', '/p/data/software', '/p/data/servers'];
  const all = [...new Set([...routes, ...extra])];
  const hits = {};
  for (const r of all) {
    try { await o.go(r); await page.waitForTimeout(300); } catch (e) { console.log('route err', r, String(e).slice(0, 120)); }
    const xs = await page.evaluate(() => { const v = window.__xs || []; window.__xs = []; return v; }).catch(() => []);
    for (const [n] of xs) (hits[r] = hits[r] || new Set()).add(n);
  }
  // Global search by author name.
  const out = Object.fromEntries(Object.entries(hits).map(([k, v]) => [k, [...v].sort((a, b) => a - b)]));
  console.log('R1_XSS_ROUTES', all.length);
  console.log('R1_XSS_HITS ' + JSON.stringify(out));
};
