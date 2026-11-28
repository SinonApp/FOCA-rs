// E2E-01: first run on the real core: /welcome, empty list (no demo projects), a new project with the test
// "internet" domain, a passive scan to completion (mini panel, stages, sources, feed), overview with core numbers.
import { harness, DOMAIN } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, click, until, api, step, text } = t;
  try {
    await o.go('');
    // Terms of use come before any screen.
    ok('first run → /terms (terms before any screen)', await t.route() === '/terms');
    ok('no demo backend: F.isDemo = false, F.isTauri = true', await ev(() => !FOCA.isDemo && FOCA.isTauri));
    ok('core: terms not accepted', (await api('terms_get')).accepted === false);
    ok('"Принимаю" disabled without checkboxes', await ev(() => document.querySelector('#ob-accept').disabled));
    await step('e01_terms');
    for (const k of ['read', 'own', 'resp']) await click('ob-check:' + k);
    await ev(() => document.querySelector('#ob-end').scrollIntoView()); await wait(400);
    ok('three of four checkboxes: button still disabled', await ev(() => document.querySelector('#ob-accept').disabled));
    await click('ob-check:age'); await wait(200);
    ok('all checkboxes and text read: button enabled', await ev(() => !document.querySelector('#ob-accept').disabled));
    await click('ob-accept'); await wait(500);
    ok('after consent → /permissions', await t.route() === '/permissions');
    const tg = await api('terms_get');
    ok('core: consent saved (version, time)', tg.accepted === true && !!tg.accepted_at, tg);
    ok('permissions screen: notifications and background work', /Уведомления/.test(await text()) && /Работа в фоне/.test(await text()));
    await step('e01_permissions');
    await click('ob-next'); await wait(400);
    ok('after permissions → /welcome', await t.route() === '/welcome');
    await step('e01_welcome');
    await click('v2w-go:2'); await wait(300);
    await click('v2w-done'); await wait(400);
    ok('after onboarding → /projects', await t.route() === '/projects');
    const list = await api('project_list');
    ok('core: no projects', list.length === 0, list);
    const empt = await text();
    ok('empty project list: "Нет проектов", no demo projects', /Нет проектов/.test(empt) && !/contoso|logistics|medlab/i.test(empt), empt.slice(0, 200));
    ok('⋮ menu without "Демо-состояний"', await ev(() => !FOCA.menuItems.some(m => m.id === 'demo' && (!m.show || m.show()))));
    await step('e01_projects_empty');

    // New project.
    await click('pj-new'); await wait(400);
    ok('/new wizard', await t.route() === '/new');
    await ev(d => { const ta = document.querySelector('#la-in'); ta.value = d; ta.dispatchEvent(new Event('input', { bubbles: true })); }, DOMAIN);
    await click('la-commit');
    await ev(() => { const c = document.querySelector('#la-pclient'); if (c) { c.value = 'ТОВ «Приклад»'; c.dispatchEvent(new Event('input', { bubbles: true })); } });
    await step('e01_new');
    const prof = await ev(() => document.querySelector('[data-act^="la-prof:"].on, .la-prof.on')?.dataset.act || '');
    // Passive profile: the target is never contacted.
    if (await ev(() => !!document.querySelector('[data-act="la-prof:passive"]'))) await click('la-prof:passive');
    await click('la-start'); await wait(600);
    const started = await until(() => FOCA.scan && FOCA.scan.running, null, 10000);
    ok('scan started', started, { prof, route: await t.route() });
    const pid = await t.project();
    ok('project created in core', (await api('project_list')).some(p => p.id === pid), pid);
    const st = await api('scan_status');
    ok('core: passive scan running', st.running && st.profile_id === 'passive' && st.active === false, st);
    // Exactly one scan indicator on the overview: the scan card at the top, or the floating bar once
    // the card scrolls away (route miniUntil); the scan screen shows the progress itself.
    const mini = await ev(() => {
      const card = document.querySelector('.page #ov-scan'), r = card && card.getBoundingClientRect(), pr = document.querySelector('.page').getBoundingClientRect();
      return { mini: document.querySelector('#mini').classList.contains('show'), route: FOCA.current(), card: !!(r && r.height > 0 && r.bottom > pr.top && r.top < pr.bottom) };
    });
    ok('one scan indicator: overview scan card or floating bar (never none, never both)', mini.route === '/p/scan' || mini.mini !== mini.card, mini);
    await step('e01_overview_running');
    await ev(() => FOCA.go('/p/scan')); await wait(2500);
    const sc = await ev(() => ({ stages: document.querySelectorAll('#scn-stages .stg, .scn-stage, [data-stage]').length, src: FOCA.scan.sources.map(s => s.id + ':' + s.status), prog: FOCA.scan.progress, label: FOCA.coreScan.stageLabel }));
    ok('scan screen: sources from core events', sc.src.length >= 5, sc);
    ok('scan screen: progress > 0', sc.prog > 0, sc);
    await step('e01_scan_running');
    const done = await until(() => FOCA.scan && !FOCA.scan.running && FOCA.db.scans.length >= 1, null, 90000);
    ok('scan finished (done event)', done, await api('scan_status'));
    await wait(800);
    const feed = await ev(() => FOCA.scan.feed.length);
    ok('live feed received findings from finding events', feed > 0, feed);
    await step('e01_scan_done');
    // Overview equals the core.
    await ev(() => FOCA.go('/p/overview')); await wait(600);
    const snap = await api('project_snapshot', { id: pid });
    const live = snap.docs.filter(d => !d.deleted).length;
    const open = snap.findings.filter(f => !['false', 'fixed'].includes(f.status)).length;
    const ov = await ev(() => ({ c: FOCA.sel.counts(), risk: FOCA.sel.risk(), txt: document.querySelector('.page').innerText }));
    ok('Overview: documents match core', ov.c.docs.total === live, { ui: ov.c.docs.total, core: live });
    ok('Overview: open findings match core', ov.c.findings.open === open, { ui: ov.c.findings.open, core: open });
    ok('Overview: people match core', ov.c.people.total === snap.people.length, { ui: ov.c.people.total, core: snap.people.length });
    const plist = (await api('project_list')).find(p => p.id === pid);
    const dbg = await ev(s => ({ snapScore: FOCA_RULES.riskScore(s.findings), uiN: FOCA.db.findings.length, snapN: s.findings.length,
      uiCrit: FOCA.db.findings.filter(f => f.sev === 'crit').map(f => [f.id, f.status, f.category, f.tags]),
      snapCrit: s.findings.filter(f => f.sev === 'crit').map(f => [f.id, f.status, f.category, f.tags]) }), snap);
    ok('Overview risk = project_list risk', ov.risk && ov.risk.score === plist.risk, { ui: ov.risk, core: plist.risk, dbg });
    ok('Overview shows "Скан завершён"', /Скан завершён/.test(ov.txt), ov.txt.slice(0, 200));
    await step('e01_overview_done');
    await ev(() => FOCA.go('/projects')); await wait(500);
    const card = await ev(() => document.querySelector('.pj-card')?.innerText || '');
    ok('project card: risk and findings from project_list', card.includes(String(plist.risk)), card);
    await step('e01_projects');
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  t.finish();
};
