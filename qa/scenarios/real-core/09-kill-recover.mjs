// E2E-09: the core process is killed (kill -9 `foca serve`) in the middle of the download stage.
// 1) The UI survives the kill (like a WebView opened before it): "running" is cleared from the core's scan_status,
//    the screen shows "scan interrupted by the system" with the lock hint, counters are not 0 (downloads are in SQLite).
// 2) Auto-resume (like the Android bridge: scan_start { resume_from, auto:true } BEFORE the UI loads) + page reload:
//    the UI sees the running scan from scan_status (sources, stage), shows the auto-resume toast, counters grow;
//    the scan completes without duplicates and history has a single record.
import { harness } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, until, api, step, serve } = t;
  const dropRefused = e0 => { for (let i = o.errs.length - 1; i >= e0; i--) if (/ERR_CONNECTION_REFUSED|harness unavailable|Failed to fetch|NetworkError/.test(o.errs[i])) o.errs.splice(i, 1); };
  try {
    serve('delay', '900', '0');
    const p = await api('project_create', { name: 'Выгрузка процесса', client: 'ТОВ «Приклад»', targets: [{ v: 'example.test', type: 'domain', active: false }], excludes: [] });
    await api('project_open', { id: p.id });
    await o.go('/p/scan');
    await ev(() => FOCA.actions['scan-start']({ profile: 'passive' }));
    await ev(() => FOCA.go('/p/scan'));
    ok('scan running, "Загрузка" stage', await until(() => FOCA.scan.running && FOCA.scan.stageIdx === 1, null, 40000));
    // Progress within the stage: entering stage 2 of N gives floor(100/N) %; wait for it to grow, otherwise the record
    // shows the stage entry. N is the full stage list (FOCA_RULES.STAGE_IDS mirrors the core's STAGES);
    // FOCA.scan.stageNames only holds the stages seen so far, so it cannot be used here.
    const stageMin = Math.floor(100 / (await ev(() => (window.FOCA_RULES && FOCA_RULES.STAGE_IDS.length) || 9)));
    ok('≥ 2 downloaded before kill, progress within stage', await until(min => FOCA.sel.counts().docs.downloaded >= 2 && FOCA.scan.progress > min, stageMin, 30000), await ev(() => FOCA.scan.progress));
    const before = await ev(() => FOCA.sel.counts().docs.downloaded);
    // kill -9 the core; the page stays open.
    let e0 = o.errs.length;
    serve('kill'); await wait(400); serve('start'); await wait(800);
    ok('core after restart: scan not running', (await api('scan_status')).running === false);
    ok('UI cleared "идёт" from core (≤ 10 s)', await until(() => !FOCA.scan.running && !FOCA.coreScan.running, null, 10000), await ev(() => ({ s: FOCA.scan.running, c: FOCA.coreScan.running })));
    dropRefused(e0);
    const rec = (await api('project_snapshot', { id: p.id })).scans.slice(-1)[0];
    ok('stopped/restart record, download stage, progress within stage', rec && rec.status === 'stopped' && rec.reason === 'restart' && rec.stage === 'download' && rec.progress > stageMin, rec && { s: rec.status, r: rec.reason, st: rec.stage, p: rec.progress });
    await ev(() => FOCA.go('/p/scan')); await wait(600);
    let tx = await t.text();
    ok('scan screen: "остановлен", no "идёт"', /остановлен/i.test(tx) && !/Этап \d из/.test(tx), tx.slice(0, 200));
    ok('downloaded counter non-zero (data survived kill -9)', await until(n => FOCA.sel.counts().docs.downloaded >= n, before, 5000), { before, now: await ev(() => FOCA.sel.counts().docs.downloaded) });
    await ev(() => FOCA.go('/p/scan-stopped')); await wait(500);
    tx = await t.text();
    ok('"Скан прерван системой" + "Продолжить с места" + "замок" hint + "Автозапуск"', /Скан прерван системой/.test(tx) && /Продолжить с места/.test(tx) && /замок/.test(tx) && /Автозапуск/.test(tx), tx.slice(0, 300));
    await step('e09_interrupted');
    // Auto-resume before the UI loads (as the Android bridge does) + page reload.
    const r = await api('scan_start', { project: p.id, profile: 'passive', resume_from: rec.id, auto: true });
    ok('core: resume of the same record, auto', r.scan_id === rec.id && r.resumed === true && r.auto === true, r);
    e0 = o.errs.length;
    await page.reload(); await wait(300);
    ok('after UI reload: scan running (from scan_status)', await until(() => window.FOCA && FOCA.scan && FOCA.scan.running && FOCA.coreScan.running, null, 15000));
    ok('"прерван системой: продолжаю" toast', await until(() => /прерван системой: продолжаю/.test((document.querySelector('#snack, .snack') || {}).innerText || ''), null, 8000));
    await ev(() => FOCA.go('/p/scan')); await wait(500);
    ok('sources and stage restored', await ev(() => FOCA.scan.sources.length > 0 && FOCA.scan.stageIdx >= 1), await ev(() => ({ src: FOCA.scan.sources.length, st: FOCA.scan.stageIdx })));
    const c0 = await ev(() => FOCA.sel.counts().docs.downloaded);
    ok('counter non-zero after reload', c0 >= before, { c0, before });
    ok('counter grows live', await until(n => FOCA.sel.counts().docs.downloaded > n, c0, 20000), { c0, now: await ev(() => FOCA.sel.counts().docs.downloaded) });
    await step('e09_resumed');
    dropRefused(e0);
    serve('delay', '0', '0');
    ok('scan ran to completion', await until(() => !FOCA.scan.running && (FOCA.db.scans.slice(-1)[0] || {}).status === 'done', null, 120000), await api('scan_status'));
    const s = await api('project_snapshot', { id: p.id });
    const urls = s.docs.filter(d => d.status === 'downloaded' || d.status === 'analyzed').map(d => d.url);
    ok('no duplicate documents', new Set(urls).size === urls.length && urls.length >= before, { n: urls.length, uniq: new Set(urls).size });
    ok('history: single done record', s.scans.length === 1 && s.scans[0].status === 'done', s.scans.map(x => x.status));
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  serve('delay', '0', '0');
  t.finish();
};
