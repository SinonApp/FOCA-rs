// E2E-11: port scan on the real core and the offline harness: "full" on example.test; the ports stage finds the
// harness HTTP port (Server banner), the excluded mail.example.test (127.0.0.2) is untouched, the log shows module ports,
// access active; the host card has a ports section; the report builds; "standard" makes no attempts.
import { harness } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, until, api, step, text } = t;
  const NET = +(process.env.E2E_NET_PORT || 8788);
  try {
    const tg = await api('terms_get');
    if (!tg.accepted) { await api('terms_accept', { version: tg.version }); await ev(() => location.reload()); await wait(1200); }
    await ev(() => { try { localStorage.setItem('foca-welcomed', '1'); } catch (e) {} });
    // Custom list: the harness port and port 1, which is surely closed; minimal site fuzzing (this scenario is about ports).
    await api('settings_set', { patch: { net: { rps: 0 }, ports: { top: 0, list: `1,${NET}` }, fuzz: { max_requests: 5, max_hosts: 1 } } });
    const p = await api('project_create', { name: 'Порты example.test', client: '', targets: [{ v: 'example.test', type: 'domain' }], excludes: ['mail.example.test'] });
    await api('project_open', { id: p.id });
    await o.go('/p/scan'); await wait(300);
    const st = await api('scan_start', { project: p.id, profile: 'full', sources: ['crt'], ports: { top: 0 } });
    ok('"Полный" started', !!st.scan_id && st.active === true, st);
    ok('scan finished', await until(() => !FOCA.scan.running, null, 180000), await api('scan_status'));
    await wait(800);
    const src = await ev(() => (FOCA.scan.sources || []).find(s => s.id === 'ports'));
    ok('"Порты (TCP)" source: ok, 1 open', src && src.status === 'ok' && src.n >= 1, src);
    const s = await api('project_snapshot', { id: p.id });
    const h = s.hosts.find(x => x.name === 'example.test') || {};
    const port = (h.ports || []).find(x => x.port === NET);
    ok('core: test-bed port found by scan, HTTP banner', port && port.source === 'scan' && /http/.test(port.service), h.ports);
    ok('core: closed port 1 not listed; ports_scan summary', !(h.ports || []).some(x => x.port === 1) && h.ports_scan && h.ports_scan.scanned === 2 && h.ports_scan.open >= 1, h.ports_scan);
    const mail = s.hosts.find(x => x.name === 'mail.example.test');
    ok('excluded mail.example.test was not scanned', !mail || !mail.ports_scan, mail && mail.ports_scan);
    const log = (await api('request_log_get', { project: p.id, limit: 100000 })).filter(r => r.module === 'ports');
    ok('log: ports attempts, active, only 127.0.0.1/scope hosts', log.length >= 2 && log.every(r => (r.access === 'active' || r.active === true) && !/127\.0\.0\.2|mail\./.test(r.url || '')), log.slice(0, 4));
    // Host card.
    await o.go('/p/entity/host/example.test'); await wait(500);
    const tx = await text();
    ok('host card: "Порты" block, "скан", summary', /Порты/.test(tx) && new RegExp(`${NET}/tcp`).test(tx) && /Скан портов/.test(tx), tx.slice(0, 300));
    await ev(() => { const r = document.querySelector('.dt-ports-sum'); if (r) r.scrollIntoView({ block: 'center' }); });
    await step('e11_host_ports');
    // Report.
    const rep = await api('report_build', { project: p.id, opts: { fmt: 'md', lang: 'ru', tpl: 'full' } });
    ok('report built', !!rep && !!(rep.name || rep.file || rep.id), rep);
    // "Standard": no connection attempts at all.
    const p2 = await api('project_create', { name: 'Порты std', client: '', targets: [{ v: 'example.test', type: 'domain' }], excludes: [] });
    await api('scan_start', { project: p2.id, profile: 'std', sources: ['crt'] });
    ok('"Стандартный" finished', await until(() => !FOCA.scan.running, null, 120000));
    await wait(500);
    const log2 = (await api('request_log_get', { project: p2.id, limit: 100000 })).filter(r => r.module === 'ports');
    ok('"Стандартный": 0 ports attempts', log2.length === 0, log2.slice(0, 3));
    await api('settings_set', { patch: { ports: { top: 100, list: '' } } });
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  t.finish();
};
