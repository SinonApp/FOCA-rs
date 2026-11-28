// E2E-04: scan stop and resume; pause/resume (paused/resumed events); process kill during a scan
// (kill -9 `foca serve`) → after restart the record is stopped/restart → resume → the scan completes.
import { harness } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, click, until, api, step, serve } = t; // o.errs holds the page console errors
  try {
    serve('delay', '1200', '0'); // documents are served slowly, so the download stage lasts ~20 s
    const p = await api('project_create', { name: 'Стоп и перезапуск', client: 'ТОВ «Приклад»', targets: [{ v: 'example.test', type: 'domain', active: false }], excludes: [] });
    await api('project_open', { id: p.id });
    await o.go('/p/scan');
    await ev(() => FOCA.actions['scan-start']({ profile: 'passive' }));
    await ev(() => FOCA.go('/p/scan'));
    ok('scan running', await until(() => FOCA.scan.running && FOCA.scan.stageIdx === 1, null, 40000));
    // The download row shows the core's queue pair ("очередь N/M") once the first progress event with a
    // total arrives: wait for that event instead of a fixed delay.
    const pair = await until(() => { const p = FOCA.scan.stageN; return p && p.stage === 'download' && p.total > 0; }, null, 20000);
    await wait(300);
    const cnt = await ev(() => ({ pair: FOCA.scan.stageN, txt: (document.querySelector('.page').innerText.match(/очередь (\d+)\/(\d+)/) || [])[0] || null }));
    ok('"очередь N/M" on the download row from the core counter (M > 0)', pair && cnt.txt && +cnt.txt.split('/')[1] > 0, cnt);
    // Outside the scan screen (overview, mini panel) the downloaded file counter grows live (snapshot on progress).
    await ev(() => FOCA.go('/p/overview')); await wait(500);
    const c0 = await ev(() => ({ n: FOCA.sel.counts().docs.downloaded, mini: (document.querySelector('#mi-s') || {}).textContent || '' }));
    await wait(5000);
    const c1 = await ev(() => ({ n: FOCA.sel.counts().docs.downloaded, mini: (document.querySelector('#mi-s') || {}).textContent || '', page: document.querySelector('.page').innerText.slice(0, 300) }));
    ok('Overview during download: downloaded count grows (snapshot and mini-panel)', c1.n > c0.n && c1.mini !== c0.mini, { c0, c1 });
    await ev(() => FOCA.go('/p/scan')); await wait(300);
    // Pause → paused, resume → resumed.
    await click('scan-pause'); await wait(700);
    let st = await api('scan_status');
    ok('pause: core paused', st.paused === true, st);
    ok('UI: "Пауза" from event', await ev(() => FOCA.scan.paused));
    await step('e04_paused');
    await click('scan-resume'); await wait(700);
    ok('resume: core not paused', (await api('scan_status')).paused === false);
    // Stop.
    await click('scan-stop'); await wait(400);
    ok('"Остановить скан?" sheet with hold', await ev(() => !!document.querySelector('.sheet.show [data-hold="scan-stop-go:user"]')));
    await ev(() => FOCA.actions['scan-stop-go']('user'));
    ok('stopped', await until(() => !FOCA.scan.running, null, 10000));
    let rec = (await api('project_snapshot', { id: p.id })).scans.slice(-1)[0];
    ok('stopped/user record with progress', rec.status === 'stopped' && rec.reason === 'user' && rec.progress > 0, rec && { s: rec.status, r: rec.reason, p: rec.progress });
    await o.go('/p/scan-stopped');
    await step('e04_stopped');
    await click('scan-continue'); await wait(800);
    ok('resume from stop point', await until(() => FOCA.scan.running, null, 10000));
    const st2 = await api('scan_status');
    ok('core: resumed, same scan_id', st2.resumed === true && st2.scan_id === rec.id, st2);
    // Kill the process during a scan.
    await wait(1500);
    const e0 = o.errs.length;
    serve('kill');
    await wait(500);
    serve('start');
    await wait(1500);
    // While the process is down, EventSource/fetch get "connection refused"; that is expected only within the restart window.
    for (let i = o.errs.length - 1; i >= e0; i--) if (/ERR_CONNECTION_REFUSED|harness unavailable/.test(o.errs[i])) o.errs.splice(i, 1);
    await o.go('/p/overview');
    rec = (await api('project_snapshot', { id: p.id })).scans.slice(-1)[0];
    ok('after kill: stopped/restart record', rec.status === 'stopped' && rec.reason === 'restart', rec && { s: rec.status, r: rec.reason, p: rec.progress, stage: rec.stage });
    await step('e04_after_restart');
    await o.go('/p/scan-stopped');
    const tx = await t.text();
    ok('stop screen: "Скан прерван системой" + "замок" hint', /прерван системой/.test(tx) && /замок/.test(tx), tx.slice(0, 160));
    await step('e04_stopped_restart');
    serve('delay', '0', '0');
    await ev(() => { window.__ev = []; FOCA.on('scan', e => window.__ev.push(e.type)); });
    await click('scan-continue'); await wait(800);
    ok('resume after restart', await until(() => FOCA.scan.running, null, 10000));
    ok('scan ran to completion', await until(() => !FOCA.scan.running && (FOCA.db.scans.slice(-1)[0] || {}).status === 'done', null, 120000), { core: await api('scan_status'), ui: await ev(() => ({ running: FOCA.scan.running, ev: window.__ev.slice(-8), last: FOCA.db.scans.slice(-1)[0] && FOCA.db.scans.slice(-1)[0].status })) });
    rec = (await api('project_snapshot', { id: p.id })).scans;
    ok('history: single record (resume reuses it)', rec.length === 1 && rec[0].status === 'done', rec.map(r => r.status));
    await step('e04_done');
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  serve('delay', '0', '0');
  t.finish();
};
