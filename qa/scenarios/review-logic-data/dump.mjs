// Dumps the text of every screen for every project plus selector numbers (read only).
// qa/shoot.sh --routes /projects --out qa/scenarios/review-logic-data --steps $PWD/qa/scenarios/review-logic-data/dump.mjs
import fs from 'fs';
export default async (page, { out }) => {
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const res = { projects: {}, errors: [] };
  page.on('pageerror', e => res.errors.push(String(e.message)));
  const ROUTES = ['/p/overview', '/p/findings', '/p/data/docs', '/p/data/people', '/p/data/hosts', '/p/data/software', '/p/data/secrets', '/p/data/emails', '/p/report-new', '/p/report-preview', '/p/reports', '/p/timeline', '/p/diff', '/p/map', '/p/monitor', '/p/scan', '/p/scope', '/p/out-of-scope', '/p/ai', '/settings/plugins'];
  await ev(() => FOCA.go('/projects')); await wait(300);
  res.projectsPage = await ev(() => document.querySelector('.page').innerText);
  const ids = await ev(() => FOCA.projects.map(p => p.id));
  for (const id of ids) {
    await ev(id => FOCA.api.project_open(id), id); await wait(200);
    const P = { sel: await ev(() => ({ counts: FOCA.sel.counts(), risk: FOCA.sel.risk(), scope: FOCA.sel.scope.info(), proj: FOCA.projects.find(p => p.id === FOCA.db.project.id), scans: FOCA.db.scans.map(s => ({ id: s.id, profile: s.profile, active: s.active, status: s.status, docs: s.docs, hosts: s.hosts, people: s.people, findings: s.findings, new_findings: s.new_findings, date: s.date })), gps: FOCA.db.gps.length, oos: FOCA.db.oos.map(o => [o.host, o.decision, !!o.blocked, o.own]), findings: FOCA.db.findings.map(f => [f.id, f.sev, f.status, f.host, f.active, f.first_scan]), tl: (() => { const t = FOCA.sel.timeline(); return { docs: t.docs.length, years: t.years, events: t.events.length }; })(), rf: (() => { const r = FOCA.sel.reportFindings({ confirmed: true, min_sev: 'all' }); return { main: r.main.length, fixed: r.fixed.length }; })() })), pages: {} };
    for (const r of ROUTES) {
      await ev(r => FOCA.go(r), r); await wait(r === '/p/map' || r === '/p/timeline' ? 400 : 250);
      P.pages[r] = await ev(() => (document.querySelector('#tb-t')?.textContent || '') + ' | ' + (document.querySelector('#tb-s')?.textContent || '') + '\n' + (document.querySelector('.page')?.innerText || ''));
    }
    // AI: preview.
    await ev(() => { FOCA.go('/p/ai'); }); await wait(200);
    await ev(() => FOCA.actions['v2ai-step'] && FOCA.actions['v2ai-step'](1)); await wait(250);
    P.pages['/p/ai#preview'] = await ev(() => document.querySelector('.page')?.innerText || '');
    await ev(() => FOCA.actions['v2ai-step'] && FOCA.actions['v2ai-step'](0)); await wait(100);
    // Search.
    for (const q of ['a', 'AXFR', 'contoso']) {
      await ev(q => { FOCA.state.searchQ = q; FOCA.go('/p/search'); }, q); await wait(250);
      P.pages['/p/search?' + q] = await ev(() => document.querySelector('.page')?.innerText || '');
    }
    res.projects[id] = P;
  }
  await ev(() => FOCA.go('/projects')); await wait(300);
  res.projectsPage2 = await ev(() => document.querySelector('.page').innerText);
  fs.writeFileSync(out + '/dump.json', JSON.stringify(res, null, 1));
};
