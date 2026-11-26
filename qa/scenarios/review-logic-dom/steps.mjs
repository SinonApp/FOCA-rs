// Logic and integration checks (DOM reads only, no code changes).
export default async (page, ctx) => { const log = {}; try { await run(page, ctx, log); } catch (e) { log.ERR = String(e && e.stack || e); } finally { console.error("L1LOG " + JSON.stringify(log)); } };
const run = async (page, { out, W, prep }, log) => {
  const ev = (f, a) => page.evaluate(f, a);
  const open = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(300); await prep(); await page.waitForTimeout(250); };
  const txt = s => ev(s => [...document.querySelectorAll(s)].map(e => e.textContent.replace(/\s+/g, ' ').trim()), s);
  const shot = async n => { await page.waitForTimeout(300); await page.screenshot({ path: `${out}/${n}.png` }); };

  // 1. Overview: numbers
  await open('/p/overview');
  log.overview = { head: await ev(() => [document.querySelector('#tb-t').textContent, document.querySelector('#tb-s').textContent]), stats: await txt('.grid.g3 .stat'), risk: await txt('.card.tap .muted'), critH: await txt('.sec-h') };
  log.counts = await ev(() => { const A = FOCA.demoFindings; const c = {}; A.forEach(f => { c[f.status + ':' + f.sev] = (c[f.status + ':' + f.sev] || 0) + 1; }); return { total: A.length, byStatus: A.reduce((o, f) => (o[f.status] = (o[f.status] || 0) + 1, o), {}), c, people: FOCA.demoData.people.length, emails: FOCA.demoData.emails.length + FOCA.demoData.roleMail.length, secrets: FOCA.demoData.secrets.length }; });
  await shot('overview');
  // 2. Findings: chip counters
  await open('/p/findings');
  log.findSeg = await txt('.fd-seg button'); log.findSums = await txt('.fd-sums .fd-sum');
  // Mark finding 3 (Jenkins, crit, new) as false positive and return to the overview.
  await ev(() => { FOCA.actions['fd-status-set']('3:false'); });
  await open('/p/overview'); // a page reload would reset the state, so this stays in one session below
  await page.goto(new URL('../../../ui/index.html#/p/finding/3', import.meta.url).href); await page.waitForTimeout(300); await prep();
  await ev(() => FOCA.actions['fd-status-set']('3:false')); await page.waitForTimeout(200);
  await ev(() => FOCA.tab('/p/overview')); await page.waitForTimeout(300);
  log.afterFalse_overview = await txt('.card.tap .muted');
  await ev(() => FOCA.go('/p/report-new')); await page.waitForTimeout(300);
  log.reportNew_default = await txt('.rp-foot-s');
  await ev(() => FOCA.go('/p/report-preview')); await page.waitForTimeout(300);
  log.preview_rows = await txt('.rp-tbl tbody tr'); log.preview_text = (await txt('.rp-paper p'))[0]; log.preview_bars = await txt('.rp-bar'); log.preview_risk = await txt('.rp-risk');
  await shot('report_preview');

  // 3. Deleting a document updates the counters
  await open('/p/data/docs');
  const before = await ev(() => ({ chip: document.querySelector('[data-act="dt-seg:docs"] .c').textContent }));
  await ev(() => { FOCA.state.dataDocs.deleted.add(1); FOCA.state.dataDocs.deleted.add(2); FOCA.render(true); });
  const after = await ev(() => ({ chip: document.querySelector('[data-act="dt-seg:docs"] .c').textContent }));
  await ev(() => FOCA.tab('/p/overview')); await page.waitForTimeout(250);
  log.deleteDoc = { before, after, overviewDocs: (await txt('.grid.g3 .stat'))[0] };
  await ev(() => FOCA.go('/p/finding/4')); await page.waitForTimeout(250);
  log.finding4_after_doc_deleted = await txt('.fd-srcdoc .row');
  await ev(() => FOCA.go('/p/entity/person/a.bondar')); await page.waitForTimeout(250);
  log.bondar_facts_after_delete = await txt('.dt-fact');
  await ev(() => FOCA.go('/p/doc/1')); await page.waitForTimeout(250);
  log.doc1_after_delete = await txt('.empty h3');

  // 4. Project switch
  await open('/projects');
  log.projects = await txt('.pj-card .pj-name, .pj-card .pj-meta');
  await ev(() => FOCA.actions['pj-open']('logistics')); await page.waitForTimeout(300);
  log.kyiv = { head: await ev(() => [document.querySelector('#tb-t').textContent, document.querySelector('#tb-s').textContent]), scope: await txt('.list .row .t'), crit: (await txt('.sec-h'))  };
  await shot('logistics_overview');
  await ev(() => FOCA.go('/p/scope')); await page.waitForTimeout(250);
  log.kyiv_scope = await txt('.kv .v');
  await ev(() => FOCA.go('/p/report-preview')); await page.waitForTimeout(250);
  log.kyiv_preview = await txt('.rp-title dd');
  await ev(() => FOCA.actions['pj-open']('dnipro')); await page.waitForTimeout(300);
  log.dnipro = { head: await ev(() => document.querySelector('#tb-s').textContent), cards: await txt('.page > .card'), stats: await txt('.grid.g3 .stat') };
  await shot('dnipro_overview');

  // 5. New target from /projects: which project does the scan go to
  await open('/projects');
  await ev(() => { FOCA.state.newTarget = 'example.org'; FOCA.go('/new'); }); await page.waitForTimeout(300);
  log.new_targets = await txt('.la-chip .la-chip-v');
  await ev(() => FOCA.actions['la-start']()); await page.waitForTimeout(400);
  log.after_start = { route: await ev(() => FOCA.current()), project: await ev(() => FOCA.project.name), scan: await ev(() => ({ running: FOCA.scan.running, active: FOCA.scan.active, target: FOCA.scan.target, profile: FOCA.scan.profile, egress: FOCA.scan.egress })) };

  // 6. Full profile: is the scan active?
  await open('/new');
  await ev(() => { FOCA.actions['la-prof']('full'); }); await page.waitForTimeout(150);
  await ev(() => FOCA.actions['la-start']()); await page.waitForTimeout(300);
  log.confirm = { route: await ev(() => FOCA.current()), targets: await txt('.page .list .row .t'), skips: await txt('.la-skip') };
  await ev(() => { FOCA.state.launch.agree = true; FOCA.actions['la-go-active'](); }); await page.waitForTimeout(400);
  log.after_active = await ev(() => ({ route: FOCA.current(), running: FOCA.scan.running, active: FOCA.scan.active, profile: FOCA.scan.profile, egress: FOCA.scan.egress, activebar: getComputedStyle(document.querySelector('#activebar')).display }));
  await ev(() => FOCA.go('/p/scan')); await page.waitForTimeout(300);
  log.scan_sub = await ev(() => document.querySelector('#tb-s').textContent);
  log.scan_sources = await txt('.scn-src .t');
  await ev(() => FOCA.scanDemo.ff(200)); await page.waitForTimeout(400);
  log.scan_finished = await txt('.scn-g .stat');
  // 7. Standard profile: no confirmation?
  await open('/new');
  log.std_badge = await txt('.la-prof.on .la-mb');

  // 8. Entities
  for (const r of ['/p/entity/software/0', '/p/entity/printer/3', '/p/entity/host/ns2.contoso.example', '/p/entity/pc/SRV-SQL02', '/p/entity/person/y.hrytsenko', '/p/entity/host/mail.contoso.example', '/p/entity/email/hr@contoso-group.example']) {
    await open(r); log['ent ' + r] = { facts: await txt('.dt-fact'), secs: await txt('.sec-h'), btn: await txt('.dt-findby .btn') };
  }
  for (const r of ['/p/graph/person/y.hrytsenko', '/p/graph/pc/SRV-SQL02', '/p/graph/host/ns2.contoso.example']) { await open(r); log['graph ' + r] = await txt('.empty h3'); }
  // 9. Problematic documents
  for (const id of [5, 12, 24, 79, 6, 1]) { await open('/p/doc/' + id); log['doc' + id] = { hero: await txt('.dt-dhero .pill, .dt-dh-s'), kv: await txt('.dt-kv .kvr'), sec: await txt('.sec-h h2'), flags: await txt('.dt-flag') }; }
  // 10. Search: findings 11-25 are not searchable
  await open('/p/search');
  await ev(() => { const i = document.querySelector('#gq'); i.value = 'AWS'; i.dispatchEvent(new Event('input')); }); await page.waitForTimeout(200);
  log.search_aws = await txt('#gres .row .t');
  await ev(() => { const i = document.querySelector('#gq'); i.value = 'AXFR'; i.dispatchEvent(new Event('input')); }); await page.waitForTimeout(200);
  log.search_axfr = await txt('#gres h3, #gres .row .t');
  // 11. Map: points without a document
  await open('/p/map');
  log.map_n = (await txt('.list .row')).length;
  await ev(() => FOCA.actions['v2m-pt']('6')); await page.waitForTimeout(250);
  log.map_pt6 = { title: await txt('.sheet .sh-h h3'), btn: await ev(() => document.querySelector('.sheet .sh-f .btn').dataset.act) };
  // 12. Scan: history, AI
  await open('/p/scan'); log.scan_hist = await txt('.scn-hr .body');
  await open('/p/monitor'); log.mon_hist = await txt('.list .row .body');
  await open('/p/ai'); log.ai_in = await txt('.list .row');
  await open('/p/diff'); log.diff = await txt('.v2d-row .body');
  await open('/settings/keys'); log.keys = await txt('.st-key .body');
  await open('/p/out-of-scope'); log.oos = await txt('.scn-oos .scn-ohost');
};
