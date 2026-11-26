// E2E-02: a hanging source (the web archive does not respond): status goes from running to slow, "skip source",
// the search stage moves on and the scan completes; the core log (logs_get) records the source start and skip.
import { harness } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, until, api, step, serve } = t;
  try {
    const pid = (await api('project_list'))[0].id;
    await api('project_open', { id: pid });
    serve('delay', '0', '600000'); // the web archive hangs for 10 minutes
    await o.go('/p/scan');
    await ev(() => FOCA.actions['scan-start']({ profile: 'passive' }));
    await ev(() => FOCA.go('/p/scan'));
    const run = await until(() => (FOCA.scan.sources.find(s => s.id === 'wayback') || {}).status === 'running', null, 30000);
    ok('web archive: running status from core event', run, await ev(() => FOCA.scan.sources.map(s => s.id + ':' + s.status)));
    const c1 = await ev(() => document.querySelector('#scn-src-wayback')?.innerText || '');
    ok('source card: "Идёт" and wait time', /Идёт/.test(c1) && /\d:\d\d/.test(c1), c1);
    const st1 = await ev(() => document.querySelector('#scn-stages, .scn-steps, .page')?.innerText.match(/опрошено \d+ из \d+/)?.[0] || '');
    ok('"Поиск" stage: "опрошено N из M" (not "4/8 источников")', /опрошено \d+ из \d+/.test(st1), st1);
    await step('e02_source_running');
    await wait(31000);
    const c2 = await ev(() => document.querySelector('#scn-src-wayback')?.innerText || '');
    ok('after 30 s: "Долго отвечает" and "Пропустить источник" button', /Долго отвечает/.test(c2) && /Пропустить источник/.test(c2), c2);
    // The remaining time comes from the core deadline (timeout_s/deadline_ms in running; triple for the archive); the UI never writes "no response" itself.
    const wb = await ev(() => { const w = FOCA.scan.sources.find(s => s.id === 'wayback') || {}; const c = FOCA.scan.sources.find(s => s.id === 'crt') || {}; return { t: w.timeoutS, d: w.deadlineMs, crt: c.timeoutS, now: Date.now() }; });
    ok('source deadline from core: timeout_s, deadline_ms; archive gets ×3', wb.t > 0 && wb.d > wb.now && (!wb.crt || wb.t === wb.crt * 3), wb);
    ok('card: "отключится сам через …", no "Нет ответа"', /отключится сам через \d+:\d\d|завершается/.test(c2) && !/Нет ответа/.test(c2), c2);
    await step('e02_source_slow');
    await ev(() => document.querySelector('[data-act="scan-skip-src:wayback"]').click());
    const sk = await until(() => (FOCA.scan.sources.find(s => s.id === 'wayback') || {}).status === 'skipped', null, 10000);
    ok('after "Пропустить": status skipped', sk);
    const past = await until(() => FOCA.scan.stageIdx >= 1 || !FOCA.scan.running, null, 30000);
    ok('"Поиск" stage finished without web archive', past, await ev(() => FOCA.scan.stageIdx));
    await step('e02_source_skipped');
    const done = await until(() => !FOCA.scan.running, null, 90000);
    ok('scan ran to completion', done, await api('scan_status'));
    const rec = (await api('project_snapshot', { id: pid })).scans.slice(-1)[0];
    ok('history record: wayback skipped', rec.status === 'done' && rec.sources.some(s => s.id === 'wayback' && s.status === 'skipped'), rec.sources);
    const logs = await api('logs_get', { level: 'info', limit: 3000 });
    ok('log: source start and skip', logs.some(l => /wayback: старт/.test(l.msg)) && logs.some(l => /wayback: пропуск/.test(l.msg)), logs.slice(-5));
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  serve('delay', '0', '0');
  t.finish();
};
