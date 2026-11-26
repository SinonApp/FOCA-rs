// Spot checks: data corruption on rescan stop, counters after reload, the IP of an excluded host inside a CIDR target,
// the HIBP plugin, an "add to scope" candidate on top of an exclusion.
// qa/shoot.sh --routes /welcome --out qa/scenarios/review-logic-data --steps $PWD/qa/scenarios/review-logic-data/s8.mjs
import fs from 'fs';
export default async (page, { out, prep }) => {
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const L = { errors: [] };
  page.on('pageerror', e => L.errors.push(String(e.message)));
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/s8_${n}.png` }); };
  const reload = async r => { await wait(150); await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + (r || '/p/overview')); await wait(300); await prep(); await wait(250); };
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(320); };
  const text = () => ev(() => ((FOCA.page() || document.querySelector('.page'))?.innerText || '').replace(/\n+/g, ' / '));
  const reset = async () => { await ev(() => FOCA.api.demo_reset()); await wait(200); await ev(() => FOCA.api.project_open('contoso')); await wait(200); };
  const cnt = () => ev(() => { const c = FOCA.sel.counts(); const d1 = FOCA.db.docs.find(d => d.id === 1); return { analyzed: c.docs.analyzed, downloaded: c.docs.downloaded, people: c.people.total, sw: FOCA.db.software.length, f: c.findings.open, secrets: c.secrets, d1: [d1.status_code, d1.author, d1.software, (d1.flags || []).join(',')], scans: FOCA.db.scans.map(s => [s.profile, s.status, s.progress, s.stage]), core: FOCA_DEMO_BACKEND.invokeSync('scan_status') }; });
  try {
    // A. Stop a rescan between the download and metadata stages, then resume.
    await reset(); await reload('/p/overview');
    L.A0 = await cnt();
    await ev(() => FOCA.actions['scan-start']({ profile: 'std' }));
    await ev(() => { FOCA.scanDemo.ff(18); return FOCA.api.scan_pause(); }); // 36%: download applied, metadata not yet
    L.A1_paused = await cnt();
    await ev(() => FOCA.api.scan_stop('user')); await wait(200);
    L.A2_stopped = await cnt();
    await reload('/p/overview'); L.A3_reload = await cnt(); L.A3_overview = await text();
    await go('/p/doc/1'); L.A3_doc1 = await text(); await shot('doc1_after_stop');
    await go('/p/data/people'); L.A3_people = await text();
    await ev(() => FOCA.actions['scan-continue']()); await wait(200);
    await ev(() => FOCA.scanDemo.ff(60)); await wait(300);
    L.A4_resumed = await cnt();
    await go('/p/overview'); L.A4_overview = await text();
    await go('/p/doc/1'); L.A4_doc1 = await text(); await shot('doc1_after_resume');
    await go('/p/data/people'); L.A4_people = await text();
    await go('/p/finding/4'); L.A4_f4 = await text();
    await go('/p/timeline'); L.A4_tl = await text();

    // B. Document deletion → reload → software/people cards.
    await reset(); await reload('/p/overview');
    await ev(() => FOCA.api.doc_delete([1])); await wait(100);
    await go('/p/entity/person/a.bondar'); L.B_before_reload = await text();
    await reload('/p/entity/person/a.bondar'); L.B_after_reload = await text();
    await go('/p/data/software'); L.B_sw_after_reload = await text();
    L.B_sel = await ev(() => ({ p: FOCA.db.people.find(p => p.login === 'a.bondar').docs, rel: FOCA.sel.related('person', 'a.bondar').docs.length, sw: FOCA.db.software.find(s => s.id === 'word2013').docs, swrel: FOCA.sel.related('software', 'word2013').docs.length, card: FOCA.projects.find(p => p.id === 'contoso').docs }));
    await go('/projects'); L.B_projects = await text();

    // C. An excluded host and its IP within a CIDR target (contoso and logistics source data).
    await reset(); await reload('/p/overview');
    L.C_contoso = await ev(() => ({ excl: FOCA.db.scope.excl, targets: FOCA.db.scope.targets, mail: FOCA.sel.scope.check('mail.contoso.example'), mailIp: FOCA.sel.scope.check('203.0.113.20'), mailHostIp: FOCA.db.hosts.find(h => h.name === 'mail.contoso.example').ip, be: FOCA_DEMO_BACKEND._scope.check(FOCA.db.scope, '203.0.113.20') }));
    await ev(() => FOCA.api.project_open('logistics')); await wait(200);
    L.C_kyiv = await ev(() => ({ excl: FOCA.db.scope.excl, targets: FOCA.db.scope.targets, crm: FOCA.sel.scope.check('crm.logistics.example'), crmIp: FOCA.sel.scope.check('198.51.100.20'), crmHost: FOCA.db.hosts.find(h => /^crm/.test(h.name)) }));
    // std wizard for logistics: the confirmation counts all /26 addresses.
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go('/new'); }); await wait(250);
    await ev(() => { FOCA.state.launch.profile = 'std'; FOCA.go('/confirm-active'); }); await wait(300);
    L.C_kyiv_confirm = await text(); await shot('kyiv_confirm_std');

    // D. Plugins: HIBP with a key set; SQLi in a project without a ban; Git log on a std scan.
    await ev(() => FOCA.api.project_open('contoso')); await wait(200);
    await go('/settings/plugin/hibp'); L.D_hibp = await text();
    await go('/settings/plugin/git'); L.D_git = await text();
    await go('/settings/plugin/iis'); L.D_iis = await text();
    await go('/settings/keys'); L.D_keys = (await text()).slice(0, 900);

    // E. Out-of-scope candidate + an exclusion for the same address.
    await ev(() => { const o = FOCA.db.oos.find(x => x.kind === 'link' && !x.blocked); FOCA.state.__o = o; return FOCA.api.scope_set({ excl: FOCA.db.scope.excl.concat(o.host) }); }); await wait(150);
    L.E_oos = await ev(() => ({ o: FOCA.state.__o, list: FOCA.db.oos.map(x => [x.host, x.decision]) }));
    await ev(() => FOCA.api.project_snapshot().then(s => { FOCA.state.__snap = s.oos.map(x => [x.host, x.decision]); })); await wait(100);
    L.E_oos_after_excl = await ev(() => FOCA.state.__snap);
    await ev(() => FOCA.actions['oos-add-go'](FOCA.state.__o.id)); await wait(300);
    L.E_after_add = await ev(() => ({ targets: FOCA.db.scope.targets.map(t => t.v), excl: FOCA.db.scope.excl, check: FOCA.sel.scope.check(FOCA.state.__o.host), oos: FOCA.db.oos.map(x => [x.host, x.decision]) }));
    await go('/p/scope'); L.E_scope = await text();

    // F. First scan of a new project: stop at download, reload, overview.
    await ev(() => FOCA.api.project_create({ name: 'stoptest.ua', client: '', targets: [{ v: 'stoptest.ua', type: 'domain', active: false }], excludes: [], contract: {} }).then(p => FOCA.api.project_open(p.id))); await wait(250);
    await ev(() => FOCA.actions['scan-start']({ profile: 'std' })); await ev(() => { FOCA.scanDemo.ff(30); return FOCA.api.scan_stop('user'); }); await wait(300);
    await reload('/p/overview'); L.F_overview = await text(); L.F_cnt = await cnt().catch(e => String(e));
    await go('/p/scan'); L.F_scan = await text();
    await go('/p/diff'); L.F_diff = await text();
  } catch (e) { L.ERR = String(e && e.stack || e); }
  fs.writeFileSync(out + '/s8.json', JSON.stringify(L, null, 1));
};
