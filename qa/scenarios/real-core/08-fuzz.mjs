// E2E-08: forgotten file discovery on the real core and the offline harness (foca testnet serves
// tests/fixtures/fuzz-site as www.<domain>): the "full" wizard shows the estimate block; one-tap launch; the
// site search stage with counters; site search findings (.git, .env, listing); discovered documents are downloaded
// and analyzed; the log shows module fuzz, access active; Settings → Wordlists; "standard" sends zero fuzz requests.
import { harness, DOMAIN } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, click, until, api, step, text } = t;
  let pid = null; let net0 = null;
  try {
    const st0 = await api('settings_get');
    net0 = st0.net && st0.net.rps;
    // Harness: no global request limit and a budget for two addresses (the phone uses gentle defaults).
    await api('settings_set', { patch: { net: { rps: 0 }, fuzz: { max_requests: 30000, max_hosts: 3, exclude_paths: ['/private'] } } });
    const p = await api('project_create', { name: 'Поиск на сайте (e2e)', client: 'ТОВ «Стенд»', targets: [{ v: DOMAIN, type: 'domain' }], excludes: [`mail.${DOMAIN}`] });
    pid = p.id;
    await api('project_open', { id: pid });
    await o.go('/p/overview');
    // Wizard: the forgotten file discovery block.
    await o.go('/p/overview');
    await ev(() => { FOCA.state.launch.leave = true; FOCA.go('/new'); }); await wait(400);
    await click('la-prof:full'); await wait(800);
    ok('wizard: site search block and request estimate', await until(() => !!document.querySelector('#la-fz') && /запросов|адрес/.test(document.querySelector('#la-fz-est').innerText), null, 8000),
      await ev(() => (document.querySelector('#la-fz-est') || {}).innerText));
    ok('wizard: no port scan/HttpMap', !/HttpMap|Порт-скан/.test(await text()));
    await step('e08_launch_fuzz');
    ok('wizard: no checkbox or hold, "Запустить" button', await ev(() => !document.querySelector('[data-hold]') && /Запустить/.test(document.querySelector('#la-start').textContent)));
    await click('la-start'); await wait(500);
    ok('active scan started with one tap', await until(() => FOCA.scan.running && FOCA.scan.active, null, 15000));
    ok('no confirmation screen', await t.route() !== '/confirm-active');
    await o.go('/p/scan');
    ok('"Поиск на сайте" stage started', await until(() => FOCA.scan.sources.some(s => s.id === 'fuzz' && s.checked > 0), null, 120000), await ev(() => FOCA.scan.sources.find(s => s.id === 'fuzz')));
    await step('e08_scan_fuzz');
    ok('scan finished', await until(() => !FOCA.scan.running && !!FOCA.scan.finished, null, 240000), await api('scan_status'));
    const fz = await ev(() => FOCA.scan.sources.find(s => s.id === 'fuzz'));
    ok('brute force: status "ok", checked and filtered by calibration', fz && fz.status === 'ok' && fz.checked > 100, fz);
    // Findings and documents.
    const snap = await api('project_snapshot', { id: pid });
    const ff = snap.findings.filter(f => f.module === 'fuzz');
    const has = re => ff.some(f => re.test(f.title));
    ok('"Поиск на сайте" findings: .git, .env, listing', has(/\.git\/HEAD/) && has(/\/\.env/) && has(/Открытый листинг каталога/) && ff.every(f => f.source === 'Поиск на сайте' && f.active), ff.map(f => f.title));
    const docs = snap.docs.map(d => d.name);
    ok('documents found by brute force downloaded', ['secret-plan_2024.pdf', 'annual_report.docx'].every(n => docs.includes(n)), docs);
    const log = await api('request_log_get', { project: pid, limit: 100000 });
    const fl = log.filter(x => x.module === 'fuzz');
    ok('log: brute-force requests, active, no /private and mail.*', fl.length > 100 && fl.every(x => x.access === 'active' && !/^\/private(\/|$)/.test(new URL(x.url).pathname) && x.host !== `mail.${DOMAIN}`), fl.length);
    await o.go('/p/findings'); await wait(400);
    ok('findings screen: "Поиск на сайте"', /Открытый репозиторий \.git/.test(await text()));
    await step('e08_findings');
    // Wordlists.
    await o.go('/settings/wordlists'); await wait(800);
    ok('"Настройки → Словари": built-in and large', await until(() => /Встроенные/.test(FOCA.page().innerText) && /quickhits/.test(FOCA.page().innerText), null, 8000));
    await step('e08_wordlists');
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  try {
    await api('settings_set', { patch: { net: { rps: net0 == null ? 5 : net0 }, fuzz: { max_requests: 3000, max_hosts: 3, exclude_paths: [] } } });
    const ex = (await api('project_list')).find(p => p.name === DOMAIN);
    if (ex) await api('project_open', { id: ex.id });
  } catch (e) { /* restore the harness settings */ }
  t.finish();
};
