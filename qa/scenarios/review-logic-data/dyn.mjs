// Dynamics: finding triage, document deletion/restore, scope, rescan/stop/resume, reload during a scan,
// launch safety. Writes qa/scenarios/review-logic-data/dyn.json. Does not change app code.
// qa/shoot.sh --routes /projects --out qa/scenarios/review-logic-data --steps $PWD/qa/scenarios/review-logic-data/dyn.mjs
import fs from 'fs';
export default async (page, { out, prep }) => {
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const L = { errors: [] };
  page.on('pageerror', e => L.errors.push(String(e.message)));
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/dyn_${n}.png` }); };
  const reload = async r => { await wait(150); await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + (r || '/p/overview')); await wait(300); await prep(); await wait(250); };
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(r === '/p/map' || r === '/p/timeline' ? 400 : 300); };
  const text = () => ev(() => ((FOCA.page() || document.querySelector('.page'))?.innerText || '').replace(/\n+/g, ' / '));
  const BASE = ['/p/overview', '/p/findings', '/p/data/docs', '/projects', '/p/report-new', '/p/ai', '/p/timeline', '/p/map', '/p/diff', '/p/scan', '/p/monitor'];
  const nums = () => ev(() => { const c = FOCA.sel.counts(); const p = FOCA.projects.find(x => FOCA.db.project && x.id === FOCA.db.project.id) || {}; return { project: FOCA.db.project && FOCA.db.project.id, docs: c.docs, people: c.people.total, hosts: c.hosts.total, f: c.findings, risk: FOCA.sel.risk().score, card: { findings: p.findings, docs: p.docs, risk: p.risk, scanning: p.scanning, scans: p.scans }, scans: FOCA.db.scans.map(s => [s.id, s.profile, s.status, s.docs, s.findings, s.new_findings, s.active, s.progress]), scan: { running: FOCA.scan.running, active: FOCA.scan.active, profile: FOCA.scan.profile, project: FOCA.scan.project }, core: FOCA_DEMO_BACKEND.invokeSync('scan_status') }; });
  const grab = async (tag, routes = BASE) => { const o = { nums: await nums(), pages: {} }; for (const r of routes) { await go(r); o.pages[r] = await text(); } L[tag] = o; return o; };
  const ONLY = (process.argv[process.argv.indexOf('--sec') + 1] || '').split(',');
  const sec = async (name, fn) => { if (process.argv.includes('--sec') && !ONLY.includes(name)) return; const t0 = Date.now(); try { await fn(); } catch (e) { L[name + '_ERR'] = String(e && e.stack || e); } L[name + '_ms'] = Date.now() - t0; };
  const reset = async () => { await ev(() => FOCA.api.demo_reset()); await wait(200); await ev(() => FOCA.api.project_open('contoso')); await wait(200); };

  // s1: finding triage.
  await sec('s1', async () => {
    await reset(); await reload('/p/overview');
    await grab('S1_base');
    await ev(() => FOCA.api.finding_set_status(3, 'false')); await wait(150);
    await grab('S1_false3');
    await ev(() => FOCA.api.finding_set_status(3, 'confirmed')); await wait(150);
    await grab('S1_conf3', ['/p/overview', '/p/findings', '/projects', '/p/report-new', '/p/report-preview', '/p/ai']);
    await reload('/p/overview');
    L.S1_after_reload = { st3: await ev(() => FOCA.db.findings.find(f => f.id === 3).status), nums: await nums() };
  });

  // s2: document deletion/restore.
  await sec('s2', async () => {
    await reset(); await reload('/p/overview');
    const ROUTES2 = ['/p/overview', '/p/data/docs', '/projects', '/p/entity/person/a.bondar', '/p/entity/person/v.tkachenko', '/p/finding/4', '/p/finding/14', '/p/map', '/p/timeline', '/p/data/software', '/p/entity/software/word2013', '/p/diff', '/p/data/secrets', '/p/search', '/p/doc/1'];
    await grab('s2_base', ROUTES2);
    L.S2_base_x = await ev(() => ({ word2013: FOCA.db.software.find(s => s.id === 'word2013').docs, gps: FOCA.db.gps.length, secrets: FOCA.db.secrets.length, os: FOCA.sel.os().map(o => [o.name, o.docs]), graph1: !!FOCA.sel.graph('doc', 1), rel_bondar: FOCA.sel.related('person', 'a.bondar').docs.length, sw_rel: FOCA.sel.related('software', 'word2013').docs.length, export_docs: null }));
    await ev(() => FOCA.api.doc_delete([1, 2])); await wait(150);
    await ev(() => { FOCA.state.searchQ = 'tes2_build'; }); 
    await grab('s2_del', ROUTES2);
    L.S2_del_x = await ev(() => ({ word2013: FOCA.db.software.find(s => s.id === 'word2013').docs, gps: FOCA.db.gps.length, secrets: FOCA.db.secrets.length, os: FOCA.sel.os().map(o => [o.name, o.docs]), graph1: !!FOCA.sel.graph('doc', 1), rel_bondar: FOCA.sel.related('person', 'a.bondar').docs.length, sw_rel: FOCA.sel.related('software', 'word2013').docs.length, people: FOCA.db.people.map(p => [p.login, p.docs]) }));
    await reload('/p/overview');
    L.S2_after_reload = await ev(() => ({ deleted: FOCA.db.docs.filter(d => d.deleted).map(d => d.id), word2013: FOCA.db.software.find(s => s.id === 'word2013').docs, people: FOCA.db.people.map(p => [p.login, p.docs]), total: FOCA.sel.counts().docs.total }));
    await ev(() => FOCA.api.doc_restore([1, 2])); await wait(150);
    L.S2_restore_x = await ev(() => ({ word2013: FOCA.db.software.find(s => s.id === 'word2013').docs, gps: FOCA.db.gps.length, total: FOCA.sel.counts().docs.total, people: FOCA.db.people.map(p => [p.login, p.docs]) }));
  });

  // s3: scope, target and exclusion.
  await sec('s3', async () => {
    await reset(); await reload('/p/overview');
    await ev(() => { const s = FOCA.db.scope; FOCA.api.scope_set({ targets: s.targets.concat({ v: 'example.org', type: 'domain', active: false }), excl: s.excl.concat('files.contoso.example') }); }); await wait(150);
    await grab('S3_changed', ['/p/overview', '/p/scope', '/p/entity/host/files.contoso.example', '/p/finding/9', '/p/finding/4', '/p/out-of-scope', '/p/findings', '/p/report-preview', '/p/data/hosts']);
    L.S3_checks = await ev(() => ({ files: FOCA.sel.scope.check('files.contoso.example'), ex: FOCA.sel.scope.check('example.org'), mail: FOCA.sel.scope.check('mail.contoso.example'), ip: FOCA.sel.scope.check('203.0.113.15'), be: FOCA_DEMO_BACKEND._scope.check(FOCA.db.scope, '203.0.113.15') }));
    // confirm-active for "standard" from the wizard (new scan).
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go('/new'); }); await wait(250);
    await ev(() => { FOCA.state.launch.profile = 'std'; FOCA.go('/confirm-active'); }); await wait(300);
    L.S3_confirm_std = await text();
    await reload('/p/overview');
    L.S3_after_reload = await ev(() => ({ targets: FOCA.db.scope.targets.map(t => t.v), excl: FOCA.db.scope.excl }));
  });

  // s4: launch safety.
  await sec('s4', async () => {
    await reset(); await reload('/p/overview');
    const tryStart = o => ev(o => FOCA.api.scan_start(o).then(r => ({ ok: true, r }), e => ({ ok: false, code: e.code, msg: e.message })), o);
    const stopNow = () => ev(() => FOCA.api.scan_stop('user').catch(() => {}));
    // medlab: contract expired, allow_active=false.
    await ev(() => FOCA.api.project_open('medlab')); await wait(200);
    L.S4_medlab_scope = await ev(() => FOCA.sel.scope.info());
    L.S4_medlab_full = await tryStart({ profile: 'full' });
    L.S4_medlab_custom_axfr = await tryStart({ profile: 'custom', modules: ['axfr'] });
    L.S4_medlab_std = await tryStart({ profile: 'std', modules: ['search', 'crt', 'wayback', 'dns', 'docs', 'alive'] });
    await stopNow(); await wait(200);
    // UI: /new std → /confirm-active on an expired contract.
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go('/new'); }); await wait(250);
    await ev(() => { FOCA.state.launch.profile = 'std'; FOCA.go('/confirm-active'); }); await wait(300);
    await ev(() => FOCA.actions['la-agree']()); await wait(200);
    L.S4_medlab_confirm_std = { text: await text(), holdDisabled: await ev(() => document.querySelector('[data-hold="la-go-active"]').disabled) };
    await shot('medlab_confirm_std_expired');
    // agro: no contract; "standard" and targets outside the contract.
    await ev(() => FOCA.api.project_open('agro')); await wait(200);
    L.S4_agro_std = await tryStart({ profile: 'std' }); await stopNow(); await wait(150);
    // New scan: entering a target in the wizard extends the scope right away.
    await ev(() => FOCA.api.project_open('contoso')); await wait(200);
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go('/new'); }); await wait(300);
    await ev(() => { const ta = document.querySelector('#la-in'); ta.value = 'evil-competitor.com\n'; ta.dispatchEvent(new Event('input')); }); await wait(300);
    L.S4_wizard_scope_after_type = await ev(() => ({ targets: FOCA.db.scope.targets.map(t => [t.v, t.active]), check: FOCA.sel.scope.check('evil-competitor.com') }));
    await ev(() => { FOCA.state.launch.profile = 'std'; FOCA.go('/confirm-active'); }); await wait(300);
    await ev(() => FOCA.actions['la-agree']()); await wait(200);
    L.S4_wizard_confirm = { text: await text(), holdDisabled: await ev(() => document.querySelector('[data-hold="la-go-active"]').disabled) };
    // Active scan: stop → contract expired → resume; contract valid → restart without confirmation.
    await reset(); await reload('/p/scan');
    L.S4_full_start = await ev(() => FOCA.actions['scan-start']({ profile: 'full', active: true }).then(r => r, e => ({ err: e.code })));
    await ev(() => FOCA.scanDemo.ff(5)); await ev(() => FOCA.api.scan_stop('user')); await wait(300);
    await ev(() => FOCA.api.scope_set({ to: '2026-11-10' })); await wait(150);
    await ev(() => FOCA.actions['scan-continue']()); await wait(300);
    L.S4_continue_expired = await nums();
    await ev(() => FOCA.api.scope_set({ to: '2026-11-30' })); await wait(150);
    // Restart from the stopped screen: no /confirm-active and no hold.
    await ev(() => FOCA.go('/p/scan-stopped')); await wait(250);
    L.S4_stopped_page = await text();
    await ev(() => FOCA.actions['scan-restart-go']()); await wait(300);
    L.S4_restart = await nums();
    await shot('restart_active_noconfirm');
    await stopNow(); await wait(200);
    // Exclusion after stopping + resume: targets come from the scan record.
    await ev(() => FOCA.api.scope_set({ excl: FOCA.db.scope.excl.concat('contoso.example') })); await wait(150);
    L.S4_resume_args = await ev(() => { const B = FOCA_DEMO_BACKEND; const orig = B.invokeSync; let got = null; B.invokeSync = (c, a) => { if (c === 'scan_start') got = a; return orig.call(B, c, a); }; return FOCA.actions['scan-continue'](), new Promise(r => setTimeout(() => { B.invokeSync = orig; r({ got, check: FOCA.sel.scope.check('contoso.example') }); }, 300)); });
    await stopNow(); await wait(200);
  });

  // s5: contoso rescan, triage during the scan, stop midway, resume.
  await sec('s5', async () => {
    await reset(); await reload('/p/overview');
    L.S5_base = await nums();
    await ev(() => FOCA.actions['scan-start']({ profile: 'std' }));
    await ev(() => FOCA.api.finding_set_status(3, 'false')); await ev(() => FOCA.api.doc_delete([7])); await wait(100);
    L.S5_triaged = await ev(() => ({ st3: FOCA.db.findings.find(f => f.id === 3).status, d7: FOCA.db.docs.find(d => d.id === 7).deleted }));
    await ev(() => FOCA.scanDemo.ff(18)); await wait(200); // progress 36: the download stage has been applied
    await grab('S5_mid', ['/p/overview', '/p/data/docs', '/p/doc/1', '/p/finding/4', '/p/data/people']);
    await ev(() => FOCA.api.scan_stop('user')); await wait(300);
    L.S5_stopped = await nums();
    await reload('/p/overview');
    await grab('S5_stopped_reload', ['/p/overview', '/p/data/docs', '/p/doc/1', '/p/scan', '/projects']);
    await ev(() => FOCA.actions['scan-continue']()); await wait(300);
    await ev(() => FOCA.scanDemo.ff(60)); await wait(300);
    await grab('S5_resumed_done', ['/p/overview', '/p/data/docs', '/p/doc/1', '/p/finding/3', '/p/scan', '/p/diff', '/p/timeline']);
    L.S5_done_x = await ev(() => ({ st3: FOCA.db.findings.find(f => f.id === 3).status, d7: FOCA.db.docs.find(d => d.id === 7).deleted, analyzed: FOCA.sel.counts().docs.analyzed, people: FOCA.db.people.length, doc1: (({ status_code, author, software, created_at }) => ({ status_code, author, software, created_at }))(FOCA.db.docs.find(d => d.id === 1)) }));
    // Clean rescan without a stop, to verify the history record rules.
    await reset(); await reload('/p/overview');
    await ev(() => FOCA.actions['scan-start']({ profile: 'std' })); await ev(() => FOCA.api.finding_set_status(5, 'confirmed')); await ev(() => FOCA.scanDemo.ff(60)); await wait(300);
    L.S5_clean_rescan = { nums: await nums(), st5: await ev(() => FOCA.db.findings.find(f => f.id === 5).status) };
    await go('/p/scan'); L.S5_clean_rescan.scanPage = await text();
    await go('/p/diff'); L.S5_clean_rescan.diff = await text();
  });

  // s6: new project via /projects → /new, full cycle, reload during the scan, project switch.
  await sec('s6', async () => {
    await reset(); await reload('/projects');
    await ev(() => { FOCA.state.newTarget = 'example.org'; FOCA.go('/new'); }); await wait(300);
    L.S6_wizard = await text();
    await ev(() => FOCA.actions['la-start']()); await wait(500);
    L.S6_started = await nums(); L.S6_route = await ev(() => FOCA.current());
    await ev(() => FOCA.scanDemo.ff(20)); await wait(200); // 40%: documents without metadata
    await grab('S6_mid', ['/p/overview', '/p/data/docs', '/projects']);
    await reload('/p/overview'); // reload during the scan
    await grab('S6_reload_mid', ['/p/overview', '/p/scan', '/projects', '/p/data/docs']);
    L.S6_after_reload_core = await ev(() => FOCA_DEMO_BACKEND.invokeSync('scan_status'));
    // New scan of the same project after the "lost" one.
    L.S6_restart = await ev(() => FOCA.api.scan_start({ profile: 'passive' }).then(r => r, e => ({ err: e.code })));
    // Project switch during the scan.
    await ev(() => FOCA.scanDemo.ff(10)); await ev(() => FOCA.api.project_open('contoso')); await wait(200);
    await grab('S6_switched', ['/p/overview', '/p/scan', '/projects']);
    await ev(() => FOCA.scanDemo.ff(60)); await wait(300);
    L.S6_contoso_after = await nums();
    await ev(() => FOCA.api.project_open(FOCA.projects.find(p => p.name === 'example.org').id)); await wait(250);
    await grab('S6_done', ['/p/overview', '/p/findings', '/p/data/docs', '/p/data/people', '/p/data/hosts', '/projects', '/p/report-new', '/p/report-preview', '/p/ai', '/p/timeline', '/p/map', '/p/diff', '/p/scan', '/p/monitor', '/p/out-of-scope', '/p/scope']);
    L.S6_sel = await ev(() => ({ counts: FOCA.sel.counts(), scans: FOCA.db.scans.map(s => [s.id, s.status, s.profile, s.docs, s.hosts, s.people, s.findings, s.new_findings]), gps: FOCA.db.gps.length, docs_first_scan: [...new Set(FOCA.db.docs.map(d => d.first_scan))] }));
  });

  // s7: build a report and check the numbers in history.
  await sec('s7', async () => {
    await reset(); await reload('/p/reports');
    await ev(() => FOCA.api.report_build({ tpl: 'Полный отчёт пентеста', fmt: 'pdf', lang: 'RU', min_sev: 'all', confirmed: false, sections: { summary: true, findings: true, fixed: true } })); await wait(200);
    L.S7_hist = await ev(() => FOCA.db.reports.map(r => [r.id, r.name, JSON.stringify(r.opts)]));
    await go('/p/reports'); L.S7_reports = await text();
    await ev(() => FOCA.actions['rp-open'](FOCA.db.reports[0].id)); await wait(350);
    L.S7_preview_new = await text();
    // Changing a status after building: does history show the new numbers?
    await ev(() => FOCA.api.finding_set_status(3, 'false')); await wait(100);
    await ev(() => FOCA.actions['rp-open'](FOCA.db.reports[0].id)); await wait(350);
    L.S7_preview_after_triage = await text();
    await ev(() => FOCA.actions['rp-open'](3)); await wait(350);
    L.S7_preview_hist3 = await text();
  });

  const tag = process.argv.includes('--sec') ? ONLY.join('_') : 'all';
  fs.writeFileSync(out + '/dyn_' + tag + '.json', JSON.stringify(L, null, 1));
};
