// Screen numbers on the REAL core and what the new scan wizard actually sends to the core.
// qa/shoot.sh --real http://127.0.0.1:8957 --routes none --out /tmp/foca-e2e/shots --steps $PWD/qa/scenarios/review-logic-core/ui_numbers.mjs
// Requires the logic-num project with scans (qa/scenarios/review-logic-core/s1_numbers.py). Prints "NUM <key> <json>" lines.
import { harness } from '../E2E/lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ev, wait, api, text, click } = t;
  const P = (k, v) => console.log('NUM ' + k + ' ' + JSON.stringify(v));
  try {
    const tg = await api('terms_get'); if (!tg.accepted) await api('terms_accept', { version: tg.version });
    await o.go('');
    await ev(() => { localStorage.setItem('foca-welcomed', '1'); }); await page.reload(); await wait(1500);
    const list = await api('project_list');
    const num = list.find(p => p.name === 'logic-num');
    await ev(id => FOCA.api.project_open(id), num.id); await wait(800);
    const s = await api('project_snapshot', { id: num.id });
    const shot = async (route, sel) => { await ev(r => FOCA.go(r), route); await wait(1200); return ev(q => [...document.querySelectorAll(q || '.page')].map(e => e.innerText).join('\n'), sel); };
    P('core', { docs: s.docs.filter(d => !d.deleted).length, findings_open: s.findings.filter(f => !['false', 'fixed'].includes(f.status)).length, people: s.people.length, hosts: s.hosts.length, sw: s.software.length, emails: s.emails.length, risk: num.risk, scans: s.scans.length });
    P('sel.counts', await ev(() => { const c = FOCA.sel.counts(); return { docs: c.docs.total, people: c.people.total, hosts: c.hosts.total, sw: c.software, f: c.findings, risk: FOCA.sel.risk() }; }));
    P('overview', (await shot('/p/overview')).replace(/\s+/g, ' ').slice(0, 900));
    P('findings', (await shot('/p/findings')).replace(/\s+/g, ' ').slice(0, 300));
    P('data', (await shot('/p/data')).replace(/\s+/g, ' ').slice(0, 600));
    P('projects', (await shot('/projects')).replace(/\s+/g, ' ').slice(0, 400));
    await ev(id => FOCA.api.project_open(id), num.id); await wait(500);
    const rl = await api('request_log_get', { project: num.id, limit: 100000 });
    P('request_log_core', rl.length);
    P('ui_requests_estimate', await ev(() => FOCA.sel.requests().total));
    const rep = (await shot('/p/reports')).replace(/\s+/g, ' ');
    P('reports_screen', rep.slice(0, 1400));
    P('reports_log_mentions', (rep.match(/Журнал запросов[^А-Я]{0,40}/g) || []).slice(0, 4));
    // Builder composition preview vs report_build with the same options.
    const rn = (await shot('/p/report-new')).replace(/\s+/g, ' ');
    P('report_new', rn.slice(0, 1200));
    const draft = await ev(() => FOCA.sel.reportFindings({ confirmed: false, min_sev: 'all' }));
    P('ui_reportFindings', { main: draft.main.length, fixed: draft.fixed.length });
    const prev = (await shot('/p/report-preview')).replace(/\s+/g, ' ');
    P('report_preview', prev.slice(0, 1500));
    P('bad_tokens', await ev(async () => {
      const out = {};
      for (const r of ['/p/overview', '/p/findings', '/p/data', '/p/data/people', '/p/data/software', '/p/data/hosts', '/p/data/docs', '/p/reports', '/p/report-new', '/p/report-preview', '/p/diff', '/p/timeline', '/p/scan', '/p/scope', '/settings/network', '/settings/sources', '/p/recon', '/p/data/recon']) {
        FOCA.go(r); await new Promise(z => setTimeout(z, 700));
        const tx = (document.querySelector('.page') || document.body).innerText;
        const m = tx.match(/.{0,40}\b(undefined|NaN|null|\[object Object\]|Invalid Date)\b.{0,40}/g);
        if (m) out[r] = m.slice(0, 4);
      }
      return out;
    }));
    P('diff', (await shot('/p/diff')).replace(/\s+/g, ' ').slice(0, 700));

    // New scan wizard: what goes into scan_start.
    const np = await api('project_create', { name: 'logic-wizard', client: 'QA', targets: ['example.test'], excludes: [] });
    await ev(id => FOCA.api.project_open(id), np.id); await wait(600);
    await ev(() => { window.__INV = []; const inv = window.__TAURI__.core.invoke; window.__TAURI__.core.invoke = (n, p) => { if (p && /scan_start|settings_set/.test(p.cmd)) window.__INV.push(JSON.parse(JSON.stringify(p))); return inv(n, p); }; });
    await ev(() => FOCA.go('/new')); await wait(1200);
    await ev(() => { const L = FOCA.state.launch; L.docs = ['pdf']; L.maxDocs = 60; L.maxSize = 1; L.depth = 1; L.ua = 'firefox'; });
    if (await ev(() => !!document.querySelector('[data-act="la-prof:passive"]'))) await click('la-prof:passive');
    await click('la-start'); await wait(1500);
    for (let i = 0; i < 400; i++) { const st = await api('scan_status'); if (!st.running) break; await wait(1000); }
    P('wizard_invokes', await ev(() => window.__INV));
    const s2 = await api('project_snapshot', { id: np.id });
    const ex = {}; s2.docs.forEach(d => ex[d.ext] = (ex[d.ext] || 0) + 1);
    P('wizard_result_exts', ex);
    P('wizard_result_maxsize_kb', Math.max(...s2.docs.map(d => +d.size || 0)));
  } catch (e) { t.ok('exception ' + e.message, false); }
  t.finish();
};
