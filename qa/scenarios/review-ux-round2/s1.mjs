// Flow 1: first run → new project → targets → scope/contract → passive scan → active phase.
import { mk } from './lib.mjs';
export default async (page, ctx) => {
  const h = mk(page, ctx, 's1'); const { tap, type, hold, back, shot, ev, note, wait } = h;
  const R = {};
  try {
    await h.go('/welcome', true);
    note('root-start', await h.cur());
    await shot('welcome');
    await tap('.v2w-next', 'Next'); await tap('.v2w-next', 'Next');
    await tap('.v2w-cons .checkrow, .v2w-cons [data-act="v2w-ok"]', 'consent');
    await shot('welcome3');
    await tap('[data-act="v2w-done"]', 'Later');
    R.welcome = h.reset();
    await type('#pj-q', 'newcorp.ua', 'target'); await tap('.pj-go', '→');
    await shot('new_project');
    note('new-title', await h.cur(), await ev(() => document.querySelector('#la-pname')?.value));
    await type('#la-in', '10.20.30.0/24', 'subnet'); await tap('[data-act="la-commit"]', '+');
    await tap('[data-act="la-adv"]', 'Advanced'); await type('#la-excl', '10.20.30.5', 'exclusion'); await tap('[data-act="la-excl-add"]', 'Add exclusion');
    await shot('new_adv');
    // Default profile?
    note('profile-default', await ev(() => document.querySelector('.la-prof.on b')?.textContent), await ev(() => document.querySelector('#la-start').textContent));
    // Start the passive scan.
    await tap('#la-start', 'Create project and start');
    await wait(500);
    R.toPassive = h.taps + R.welcome;
    note('after-start', await h.cur(), await ev(() => ({ proj: FOCA.project && FOCA.project.name, scan: FOCA.scan && { running: FOCA.scan.running, active: FOCA.scan.active, project: FOCA.scan.project, prof: FOCA.scan.profile } })));
    await shot('overview_passive');
    await ev(() => FOCA.scanDemo.ff(80)); await wait(600);
    await shot('overview_done');
    note('fab-covered', await ev(() => { const f = document.querySelector('#fab').getBoundingClientRect(), s = document.querySelector('#snack'); const r = s.getBoundingClientRect(); return { fab: [f.top, f.bottom], snack: [r.top, r.bottom], snackShow: s.classList.contains('show'), hit: document.elementFromPoint(f.left + f.width / 2, f.top + f.height / 2)?.className }; }));
    await wait(4500);
    h.reset();
    // Active phase: new scan FAB → full → next.
    await tap('#fab', 'FAB New scan');
    await shot('newscan');
    note('newscan-targets', await ev(() => FOCA.state.launch.targets.map(t => t.v + (t.active ? '(A)' : ''))));
    await tap('[data-act="la-prof:full"]', 'Full');
    await tap('#la-start', 'Next: scope check');
    await shot('confirm_nocontract');
    note('confirm', await ev(() => ({ why: document.querySelector('.la-foot-w')?.textContent, toscope: !!document.querySelector('.la-toscope') })));
    await tap('.la-toscope', 'Open contract and scope');
    await shot('scope');
    await tap('[data-act="la-contract"]', 'Add contract');
    await shot('contract_sheet');
    const fields = await ev(() => [...document.querySelectorAll('.sheet.show input, .sheet.show [data-act]')].map(e => e.id || e.dataset.act));
    note('contract-fields', fields);
    await type('#ct-num', '17/2026', 'number');
    await type('#ct-client', 'NewCorp', 'client');
    note('date-input', await ev(() => [...document.querySelectorAll('.sheet.show input')].map(i => i.id + ':' + i.type + ':' + i.value)));
    await type('#ct-from', '2026-11-01', 'term from'); await type('#ct-to', '2026-12-31', 'term to');
    // Enable "allow active phase".
    await tap('.sheet.show [data-act="la-ct-active"]', 'allow active');
    await shot('contract_filled');
    await tap('[data-act="la-contract-save"]', 'Save contract');
    await shot('scope_contract');
    note('scope-after-contract', await ev(() => ({ info: FOCA.sel.scope.info(), targets: (FOCA.db.scope.targets || []).map(t => t.v + ':' + t.active) })));
    // Targets: allow active.
    const nT = await ev(() => document.querySelectorAll('[data-act^="la-tperm:"]').length);
    for (let i = 0; i < nT; i++) { await tap(`[data-act="la-tperm:${i}"]`, 'target ' + i); await shot('tperm' + i); const ok = await tap(`.sheet.show [data-act="la-tperm-set:${i}:1"]`, 'Active allowed'); if (!ok) await tap('.sheet.show [data-act="sheet-close"]', 'close'); }
    await shot('scope_active');
    note('scope-after', await ev(() => (FOCA.db.scope.targets || []).map(t => t.v + ':' + t.active)));
    await back('Back to confirmation');
    note('after-back', await h.cur());
    await shot('confirm_after_scope');
    await tap('[data-act="la-agree"]', 'checkbox');
    await shot('confirm_ready');
    await hold('[data-hold="la-go-active"]', 'hold');
    await wait(500);
    note('after-active', await h.cur(), await ev(() => ({ active: FOCA.scan.active, running: FOCA.scan.running, bar: document.querySelector('#activebar').classList.contains('show') })));
    R.active = h.taps;
    await shot('after_active');
    // Where does Back from the overview lead after launch?
    await back(); note('back-from-overview', await h.cur());
    await back(); note('back-from-projects', await h.cur(), await ev(() => location.hash));
    await ev(() => FOCA.scanDemo.ff(200));
  } catch (e) { note('ERR', e.message); }
  console.log('s1', JSON.stringify({ R, log: h.log }, null, 0));
};
