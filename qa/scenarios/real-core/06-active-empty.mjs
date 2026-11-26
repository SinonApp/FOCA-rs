// E2E-06: active phase on the real core: "full" starts with one tap on "start" in the wizard, without a
// project toggle, checkbox, hold or confirmation log; red "active mode" bar; then stop.
// E2E-07 (also here): empty states of the screens on a new project without a scan.
import { harness } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, click, until, api, step, text } = t;
  try {
    const pid = (await api('project_list')).find(p => p.name === 'example.test').id;
    await api('project_open', { id: pid });
    const sc = await api('scope_get', { id: pid });
    ok('scope: no allow_active and no "активно" target marks', !('allow_active' in sc) && sc.targets.every(x => !('active' in x)), sc);
    // Wizard: "full" → "start".
    await o.go('/p/overview');
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go('/new'); }); await wait(400);
    await click('la-prof:full'); await wait(400);
    ok('wizard: "Запустить" button, no checkbox or hold', await ev(() => /Запустить/.test(document.querySelector('#la-start').textContent) && !document.querySelector('[data-hold]') && !/разрешение на активную/.test(FOCA.page().innerText)));
    await step('e06_full_ready');
    t.serve('delay', '0', '6000'); // the web archive answers in 6 s, so the active scan cannot finish before the checks
    await click('la-start'); await wait(600);
    ok('"Полный" started by core with one tap', await until(() => FOCA.scan.running && FOCA.scan.active, null, 15000), await api('scan_status'));
    ok('no confirmation screen', await t.route() !== '/confirm-active');
    const st = await api('scan_status');
    ok('core: level active, profile "Полный"', st.running && st.active === true && st.profile_id === 'full', st);
    ok('red "Активный режим" bar', await ev(() => document.querySelector('#activebar').classList.contains('show')));
    ok("no confirmation log (core doesn't know active_acks)", await api('active_acks', { project: pid }).then(() => false, () => true));
    await step('e06_active_running');
    t.serve('delay', '0', '0');
    await api('scan_stop', { reason: 'user' });
    await until(() => !FOCA.scan.running, null, 15000);
    await wait(500);
    ok('bar removed after stop', await ev(() => !document.querySelector('#activebar').classList.contains('show')));
    // Empty states of a new project.
    const p = await api('project_create', { name: 'Пустой проект', client: '', targets: [{ v: 'empty.test', type: 'domain' }], excludes: [] });
    await api('project_open', { id: p.id });
    for (const r of ['/p/overview', '/p/findings', '/p/data/docs', '/p/data/people', '/p/data/hosts', '/p/data/secrets', '/p/reports', '/p/scan', '/p/scan-stopped', '/p/out-of-scope', '/p/map', '/p/timeline', '/p/diff', '/p/graph/person/x', '/p/doc/1', '/p/finding/1', '/p/entity/host/x', '/p/ai', '/p/monitor', '/p/preflight', '/p/search']) {
      await o.go(r);
      const tx = await text();
      ok(`empty state ${r}: no foreign/demo data`, !/contoso|a\.bondar|undefined|NaN/i.test(tx) && tx.trim().length > 10, tx.slice(0, 100));
      await step('e07_empty' + r.replace(/[^\w]+/g, '_'));
    }
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  t.finish();
};
