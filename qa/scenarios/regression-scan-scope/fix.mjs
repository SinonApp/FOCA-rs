// Regression checks: scan driven by core events, new project, scope, Back, tap targets, all projects.
// qa/shoot.sh --routes /projects --out qa/scenarios/regression-scan-scope --steps $PWD/qa/scenarios/regression-scan-scope/fix.mjs
export default async (page, { out, W, prep }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const sfx = await page.evaluate(() => `${innerWidth}_fs${getComputedStyle(document.documentElement).getPropertyValue('--fs').trim() || 1}_${document.documentElement.dataset.theme}`);
  const shot = async n => { await page.waitForTimeout(350); await page.screenshot({ path: `${out}/fix_${n}_${sfx}.png` }); };
  const go = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(250); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  try {
    // The overview updates on events and the FAB appears after completion.
    await go('/p/overview');
    ok('UX6 FAB "Новый скан" before scan', await ev(() => document.querySelector('#fab').classList.contains('show')));
    await ev(() => FOCA.actions['scan-start']({ profile: 'passive' }));
    await wait(150);
    const p1 = await ev(() => ({ running: FOCA.scan.running, fab: document.querySelector('#fab').classList.contains('show'), card: document.querySelector('.page .pbar i')?.style.width, mini: document.querySelector('#mini').classList.contains('show') }));
    ok('UX6 Overview immediately shows the running scan (without leaving the tab)', p1.running && !p1.fab && p1.mini, p1);
    await wait(1500);
    const p2 = await ev(() => document.querySelector('.page .pbar i')?.style.width);
    ok('UX6 Overview progress grows without navigation', p2 && p2 !== p1.card, { before: p1.card, after: p2 });
    await shot('overview_running');
    await wait(6000);
    const p3 = await ev(() => ({ running: FOCA.scan.running, fab: document.querySelector('#fab').classList.contains('show'), title: [...document.querySelectorAll('.page .card')][0]?.textContent.slice(0, 60), scans: FOCA.db.scans.length }));
    ok('UX6 after finish FAB "Новый скан" in place, "Скан завершён" card', !p3.running && p3.fab && /завершён/.test(p3.title), p3);
    // The scan summary matches the history data.
    await ev(() => FOCA.go('/p/scan')); await wait(300);
    const fin = await ev(() => { const r = FOCA.db.scans[FOCA.db.scans.length - 1]; const v = [...document.querySelectorAll('#scn-fin .stat .v')].map(e => e.textContent.replace(/\s/g, '')); return { v, rec: [r.docs, r.findings, r.hosts].map(String), prof: r.profile }; });
    ok('logic #10 scan summary from history record', JSON.stringify(fin.v) === JSON.stringify(fin.rec) && fin.prof === 'Пассивный', fin);
    await shot('scan_finished');

    // Sources come from the scan, key status from settings; "set key" opens the key sheet.
    await go('/p/scan');
    // A source without a key (Google CSE was removed): clear the SearXNG URL and restore it after the check.
    await ev(() => FOCA.api.key_delete('searx')); await wait(100);
    await ev(() => FOCA.actions['scan-start']({ profile: 'std', open: true })); await wait(200);
    const src = await ev(() => FOCA.scan.sources.map(s => s.id));
    ok('logic #25 scan sources without Bing/Google scraping', src.length > 0 && !src.some(x => /bing|^google$/.test(x)), src);
    ok('logic #25 Google CSE removed from sources', !src.includes('gcse'), src);
    // A paid source without a key is hidden on the scan screen; there are no "set key" buttons.
    ok('logic #26 SearXNG without URL: hidden on scan screen', await ev(() => !document.querySelector('#scn-src-searx') && !/Указать ключ/.test(FOCA.page().textContent)));
    await ev(() => FOCA.api.key_set('searx', 'https://searx.local:8888')); await wait(100);
    // The feed comes from F.db.findings (severities match).
    await ev(() => FOCA.scanDemo.ff(30)); await wait(300);
    const feed = await ev(() => [...document.querySelectorAll('#scn-feed [data-fid]')].map(r => { const f = FOCA.db.findings.find(x => x.id === +r.dataset.fid); return { t: r.querySelector('.t').textContent === (f && f.title), sev: r.querySelector('.pill').textContent }; }));
    ok('logic #31 feed: findings from F.db.findings', feed.every(x => x.t), feed.slice(0, 3));
    await ev(() => FOCA.scanDemo.ff(60)); await wait(300);

    // Network loss → "offline" pause, then auto-resume.
    await go('/p/scan');
    await ev(() => FOCA.actions['scan-start']({ profile: 'passive' })); await wait(200);
    await ev(() => FOCA.setOffline(true)); await wait(250);
    const off = await ev(() => ({ paused: FOCA.scan.paused, reason: FOCA.scan.pauseReason, mini: document.querySelector('#mi-t').textContent, banner: !!document.querySelector('#scn-pbn'), sub: document.querySelector('#tb-s').textContent }));
    ok('UX10 no network → pause with reason', off.paused && off.reason === 'offline' && off.banner && /нет сети/i.test(off.sub), off);
    await shot('scan_offline');
    const st0 = await ev(() => FOCA_DEMO_BACKEND.invokeSync('scan_status')); 
    ok('UX10 pause reached the core (scan_status.paused)', st0.paused === true, st0);
    await ev(() => FOCA.setOffline(false)); await wait(300);
    ok('UX10 network back → scan resumed automatically', await ev(() => !FOCA.scan.paused && FOCA.scan.running && !FOCA_DEMO_BACKEND.invokeSync('scan_status').paused));
    await ev(() => FOCA.scanDemo.ff(60)); await wait(300);

    // Active mode: red bar, egress IP from settings, kill switch → stop.
    await go('/p/scan');
    await ev(() => FOCA.actions['scan-start']({ profile: 'full', active: true, open: true })); await wait(300);
    const act = await ev(() => ({ bar: document.querySelector('#activebar').classList.contains('show'), ip: document.querySelector('#ab-ip').textContent, net: FOCA.db.settings.net.out_ip, card: !!document.querySelector('#scn-act'), ks: document.querySelector('.scn-ks')?.textContent }));
    ok('logic #27 active mode: bar and IP from settings.net', act.bar && act.card && act.ip.includes(act.net) && /остановится/.test(act.ks), act);
    await shot('scan_active');
    await ev(() => FOCA.scanDemo.ff(14));
    await ev(() => FOCA.actions['scan-vpn-lost']()); await wait(400);
    const vpn = await ev(() => ({ route: FOCA.current(), running: FOCA.scan.running, last: FOCA.db.scans[FOCA.db.scans.length - 1], text: document.querySelector('.scn-why p')?.textContent }));
    ok('UX20 VPN drop in active mode → kill switch stop, text from settings', vpn.route === '/p/scan-stopped/vpn' && !vpn.running && vpn.last.status === 'stopped' && vpn.last.reason === 'vpn' && vpn.text.includes(await ev(() => FOCA.db.settings.net.label)), { route: vpn.route, text: vpn.text });
    await shot('stopped_vpn');
    const prog = vpn.last.progress;
    await ev(() => document.querySelector('.scn-acts [data-act="scan-continue"]').click()); await wait(400);
    // Resuming the active phase takes one tap, without a confirmation screen.
    ok('active phase "Продолжить": no confirmation screen', await ev(() => FOCA.current() !== '/confirm-active' && !document.querySelector('[data-hold]')));
    const cont = await ev(() => ({ route: FOCA.current(), running: FOCA.scan.running, p: FOCA.scan.progress, resumed: FOCA.scan.resumed }));
    ok('logic #34/resume from stop point (resume_from)', cont.running && cont.p >= prog && cont.resumed, { prog, cont });
    await ev(() => FOCA.scanDemo.ff(60)); await wait(300);

    // Battery: pause per settings, threshold from settings.
    await go('/p/scan');
    await ev(() => FOCA.actions['scan-start']({ profile: 'passive' })); await wait(200);
    await ev(() => FOCA.actions['scan-stop-go']('battery')); await wait(300);
    const bat = await ev(() => ({ paused: FOCA.scan.paused, reason: FOCA.scan.pauseReason, txt: document.querySelector('#scn-pbn')?.textContent || '', thr: FOCA.db.settings.power.batt }));
    ok('logic #28 low battery → pause (batt_action=pause), threshold from settings', bat.paused && bat.reason === 'battery' && bat.txt.includes(bat.thr + '\u00a0%'), bat);
    await ev(() => FOCA.actions['scan-resume']()); await ev(() => FOCA.scanDemo.ff(60)); await wait(300);

    // Out-of-scope candidates from data, "own" by rule, "add to scope" → scope_set.
    await go('/p/out-of-scope');
    const oos = await ev(() => FOCA.db.oos.map(o => ({ h: o.host, own: o.own, b: !!o.blocked })));
    const az = oos.find(o => /azurewebsites/.test(o.h));
    ok('logic #6 dangling CNAME: own=false and blocked', az && !az.own && az.b, az);
    ok('logic #6 blocked one has no "В скоуп" button', await ev(() => [...document.querySelectorAll('.scn-oos')].filter(c => /azurewebsites/.test(c.textContent)).every(c => !c.querySelector('[data-act^="oos-add"]'))));
    const cand = await ev(() => FOCA.db.oos.find(o => !o.blocked && o.decision === 'new'));
    await ev(id => FOCA.actions['oos-add-go'](id), cand.id); await wait(300);
    const added = await ev(h => ({ inScope: FOCA.sel.scope.allows(h), target: FOCA.db.scope.targets.find(t => t.v === h), dec: FOCA.db.oos.find(o => o.host === h)?.decision }), cand.host);
    ok('logic #6 "В скоуп" adds the target to scope and saves the decision', added.inScope && added.target && !('active' in added.target) && added.dec === 'scope', added);
    await shot('oos_after_add');
    await ev(() => FOCA.actions['scan-start']({ profile: 'passive' })); await ev(() => FOCA.scanDemo.ff(60)); await wait(300);
    ok('logic #6 decision not reset by a new scan', await ev(h => FOCA.db.oos.find(o => o.host === h)?.decision === 'scope', cand.host));

    // A new target from /projects creates a NEW project.
    await go('/projects');
    await page.fill('#pj-q', 'newcorp.ua'); await page.keyboard.press('Enter'); await wait(400);
    const nw = await ev(() => ({ route: FOCA.current(), title: document.querySelector('#tb-t').textContent, pname: document.querySelector('#la-pname')?.value, prof: FOCA.state.launch.profile, targets: FOCA.state.launch.targets.map(t => t.v) }));
    ok('UX2 "Новый проект" wizard: name from first domain, passive by default, targets not from contoso', nw.title === 'Новый проект' && nw.pname === 'newcorp.ua' && nw.prof === 'passive' && JSON.stringify(nw.targets) === '["newcorp.ua"]', nw);
    await page.fill('#la-pclient', 'ТОВ «Нью Корп»');
    await shot('new_project');
    await ev(() => document.querySelector('#la-start').click()); await wait(500);
    const np = await ev(() => ({ route: FOCA.current(), proj: FOCA.db.project, scope: FOCA.db.scope.targets.map(t => t.v), running: FOCA.scan.running, scanProj: FOCA.scan.project }));
    ok('logic #7 newcorp.ua project created, scan runs in it', np.proj.name === 'newcorp.ua' && np.proj.client === 'ТОВ «Нью Корп»' && np.scope.join() === 'newcorp.ua' && np.running && np.scanProj === np.proj.id && np.route === '/p/overview', np);
    await ev(() => FOCA.scanDemo.ff(60)); await wait(400);
    ok('logic #7 new project data: for its target', await ev(() => FOCA.db.docs.length > 0 && FOCA.db.docs.every(d => d.host.endsWith('newcorp.ua'))));

    // New scan in a project: targets from the scope; "standard" and "full" start with one tap.
    await ev(() => FOCA.api.project_open('logistics')); await go('/p/overview');
    await ev(() => FOCA.actions['new-scan']()); await wait(300);
    const ns = await ev(() => ({ title: document.querySelector('#tb-t').textContent, t: FOCA.state.launch.targets.map(t => t.v), scope: FOCA.db.scope.targets.map(t => t.v) }));
    ok('UX24 "Новый скан": targets from project scope', ns.title === 'Новый скан' && JSON.stringify(ns.t) === JSON.stringify(ns.scope), ns);
    await ev(() => FOCA.actions['la-prof']('std')); await wait(150);
    ok('button: "Запустить", no "Далее: проверка скоупа"', await ev(() => /Запустить/.test(document.querySelector('#la-start').textContent) && !/Далее/.test(FOCA.page().innerText)));
    await ev(() => document.querySelector('#la-start').click()); await wait(300);
    const cf = await ev(() => ({ route: FOCA.current(), running: FOCA.scan.running, prof: FOCA.scan.profile }));
    ok('"Стандартный" starts with one tap', cf.running && cf.route === '/p/overview' && cf.prof === 'Стандартный', cf);
    await ev(() => FOCA.scanDemo.ff(60)); await wait(300);
    // "Full" in a project that used to have active checks disabled also starts right away.
    await ev(() => FOCA.api.project_open('medlab')); await ev(() => { FOCA.state.launch.leave = true; FOCA.go('/new'); }); await wait(200);
    await ev(() => FOCA.actions['la-prof']('full')); await ev(() => document.querySelector('#la-start').click()); await wait(300);
    const cm = await ev(() => ({ route: FOCA.current(), running: FOCA.scan.running, active: FOCA.scan.active, bar: document.querySelector('#activebar').classList.contains('show') }));
    ok('"Полный" starts with one tap, red active-mode bar', cm.running && cm.active && cm.bar && cm.route === '/p/overview', cm);
    await shot('full_started');
    await ev(() => FOCA.scanDemo.ff(60)); await wait(300);
    await go('/p/scope');
    ok('"Скоуп": no "Разрешить активные проверки" toggle and no "Разрешено активно" marks', await ev(() => /Скоуп/.test(document.body.innerText) && !/Разрешено активно|Только пассивно|Разрешить активные/.test(FOCA.page().innerText)));

    // Add a target and an exclusion directly in the scope; delete the exclusion with undo.
    await ev(() => FOCA.actions['la-tadd']()); await wait(300);
    await page.fill('#la-tv', 'portal.clinic.example'); await wait(100);
    const hint = await ev(() => document.querySelector('#la-tvh').textContent);
    await ev(() => FOCA.actions['la-tadd-go']()); await wait(300);
    ok('UX3 target added via sheet with type detection', hint.startsWith('Домен') && await ev(() => FOCA.db.scope.targets.some(t => t.v === 'portal.clinic.example')), hint);
    await ev(() => FOCA.actions['la-xadd']()); await wait(300);
    await page.fill('#la-xv', '192.0.2.0/24'); await ev(() => FOCA.actions['la-xadd-go']()); await wait(300);
    const ex1 = await ev(() => FOCA.db.scope.excl.slice());
    await ev(() => FOCA.actions['la-xdel'](String(FOCA.db.scope.excl.indexOf('192.0.2.0/24')))); await wait(300);
    const ex2 = await ev(() => ({ excl: FOCA.db.scope.excl.slice(), snack: document.querySelector('#snack .sn-a')?.textContent }));
    await ev(() => document.querySelector('#snack .sn-a').click()); await wait(300);
    const ex3 = await ev(() => FOCA.db.scope.excl.slice());
    ok('UX18 exclusion: add → delete → "Отменить" restores', ex1.includes('192.0.2.0/24') && !ex2.excl.includes('192.0.2.0/24') && ex2.snack === 'Отменить' && ex3.includes('192.0.2.0/24'), { ex1, ex2, ex3 });
    await shot('scope_medlab');

    // A key added in settings enables its source automatically; the wizard has no "set" button.
    await ev(() => FOCA.api.key_delete('shodan')); await wait(100);
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go('/new'); FOCA.actions['la-adv'](); }); await wait(300);
    ok('UX13 no "Указать" buttons in the wizard', await ev(() => !/Указать/.test(FOCA.page().textContent) && !document.querySelector('[data-act^="la-key"]')));
    await ev(() => FOCA.openKeySheet('shodan')); await wait(400);
    await page.fill('#st-kv', 'shodan_demo_key_1234567890');
    await ev(() => { const b = [...document.querySelectorAll('.sheet.show .sh-f .btn')].pop(); b.click(); }); await wait(500);
    ok('UX13 source enabled after saving the key', await ev(() => ((FOCA.db.settings.sources || {}).shodan || {}).enabled !== false && FOCA.db.settings.keys.shodan.status === 'ok'));
    // Proxy: a single one, from settings, with "check".
    await ev(() => FOCA.actions['la-netcheck']()); await wait(300);
    const px = await ev(() => ({ row: document.querySelector('.la-net')?.textContent, nc: document.querySelector('.la-nc')?.textContent, sel: !!document.querySelector('#la-proxy'), ip: FOCA.db.settings.net.out_ip }));
    ok('UX14 proxy from settings + "Проверить"', !px.sel && px.row.includes(px.ip) && px.nc.includes(px.ip), px);
    // Document types and the TCP module.
    const types = await ev(() => [...document.querySelectorAll('.la-docs .chip')].map(c => c.textContent.slice(1)));
    ok('logic #37 document types per spec F-5', ['doc','docx','xls','xlsx','ppt','pptx','pdf','odt','ods','odp','sxw','svg','indd','rdp','ica','jpg','png','tiff','heic','lnk'].every(t => types.includes(t)), types.join(' '));
    await ev(() => FOCA.actions['la-prof']('custom')); await wait(200);
    ok('logic #37 "Проверка живости (TCP)" module', await ev(() => [...document.querySelectorAll('.la-mod .t')].some(t => /живости \(TCP\)/.test(t.textContent))));
    await shot('new_adv');

    // Back after opening a deep link.
    for (const [r, want] of [['/p/scan', '/p/overview'], ['/p/finding/1', '/p/overview'], ['/settings/keys', '/settings'], ['/p/overview', '/projects']]) {
      await go(r);
      await ev(() => FOCA.back()); await wait(300);
      const got = await ev(() => FOCA.current());
      ok(`UX5 "Назад" from ${r} → ${want}`, got === want, got);
    }
    // Toggle tap targets are ≥ 48 px.
    await go('/settings/network');
    const tg = await ev(() => { const t = document.querySelector('.toggle'); const r = t.getBoundingClientRect(); const b = getComputedStyle(t, '::before'); return { h: r.height - parseFloat(b.top) - parseFloat(b.bottom), w: r.width - parseFloat(b.left) - parseFloat(b.right) }; });
    ok('UX22 .toggle: tap zone ≥ 48 px', tg.h >= 48 && tg.w >= 48, tg);

    // All projects: no contoso data anywhere, an empty project shows empty states.
    const ids = await ev(() => FOCA.projects.map(p => p.id));
    for (const id of ids) {
      await ev(id => FOCA.api.project_open(id), id);
      for (const r of ['/p/overview', '/p/scan', '/p/scope', '/p/out-of-scope', '/new', '/p/scan-stopped/vpn']) {
        await ev(r => { FOCA.state.launch.leave = true; FOCA.reset(['/projects', '/p/overview', r].filter((x, i, a) => a.indexOf(x) === i)); }, r); await wait(120);
        if (id === 'contoso') continue;
        const txt = await ev(() => document.querySelector('.page').innerText + ' ' + document.querySelector('#tb-s').textContent);
        ok(`project ${id} ${r}: no contoso data`, !/contoso|ПТ-2026\/114|203\.0\.113\./i.test(txt), txt.match(/.{0,30}(contoso|ПТ-2026\/114|203\.0\.113\.).{0,30}/i)?.[0]);
      }
    }
    await ev(() => FOCA.api.project_open('dnipro')); 
    await ev(() => FOCA.reset(['/projects', '/p/overview', '/p/scan'])); await wait(200); await shot('dnipro_scan');
    ok('empty project: history empty, no candidates', await ev(() => /Сканов в этом проекте ещё не было/.test(document.querySelector('.page').innerText) && FOCA.db.oos.length === 0));
    await ev(() => FOCA.go('/p/out-of-scope')); await wait(200);
    ok('empty project: "Вне скоупа": empty state', await ev(() => !!document.querySelector('.page .empty')));
    await ev(() => FOCA.go('/p/scope')); await wait(200); await shot('dnipro_scope');
    ok('empty project: scope without contract or active-checks toggle, no word "договор"', await ev(() => /Активная фаза/.test(document.querySelector('.page').innerText) && !/оговор|выключены|Разрешить активные/.test(document.querySelector('.page').innerText)));
    await ev(() => FOCA.go('/p/scan-stopped/vpn')); await wait(200); await shot('dnipro_stopped');
    // Projects: new project card, archiving via project_update.
    await go('/projects');
    await ev(() => FOCA.actions['pj-archive']('agro')); await wait(300);
    ok('archive: project_update(archived) and "Архив" line', await ev(() => FOCA.projects.find(p => p.id === 'agro').archived && !document.querySelector('[data-pj="agro"]') && !!document.querySelector('.pj-arch')));
    await shot('projects');
  } catch (e) { fails++; log.push(['FAIL', 'exception', String(e && e.stack || e).slice(0, 400)]); }
  console.error(log.map(l => `${l[0]} ${l[1]}${l[0] === 'FAIL' || process.env.W1V ? ' ' + JSON.stringify(l[2] ?? '') : ''}`).join('\n'));
  console.error(`regression-scan-scope: ${log.length - fails} OK, ${fails} FAIL`);
};
