// E2E-10: site recon on the real core and the offline harness: a passive scan with the recon sources:
// home page/favicon/JS from the archived copy (no requests to the target), robots.txt from CDX, grep.app with a challenge →
// "blocked" status without failing the scan; data segments and the website and technologies report section.
import { harness } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, until, api, step, text } = t;
  try {
    // The scenario can run alone (E2E_ONLY="10"): accept the terms with the current version and complete onboarding.
    const tg = await api('terms_get');
    if (!tg.accepted) { await api('terms_accept', { version: tg.version }); await ev(() => location.reload()); await wait(1200); }
    await ev(() => { try { localStorage.setItem('foca-welcomed', '1'); } catch (e) {} });
    const p = await api('project_create', { name: 'Разведка example.test', client: '', targets: [{ v: 'example.test', type: 'domain' }], excludes: [] });
    await api('project_open', { id: p.id });
    await o.go('/p/overview'); await wait(300);
    const st = await api('scan_start', { project: p.id, profile: 'passive', sources: ['recon', 'wellknown', 'buckets', 'grepapp'] });
    ok('scan with recon started', !!st.scan_id, st);
    ok('scan finished', await until(() => !FOCA.scan.running, null, 90000), await api('scan_status'));
    await wait(800);
    const s = await api('project_snapshot', { id: p.id });
    const r = s.recon || {};
    ok('core: snapshot.recon, from archived copy', r.level === 'external' && r.sites && r.sites[0] && r.sites[0].via === 'archive', r.sites);
    ok('core: jQuery 1.8.2 "устарело", Nginx', (r.tech || []).some(x => x.name === 'jQuery' && x.version === '1.8.2' && x.outdated) && (r.tech || []).some(x => x.name === 'Nginx'), r.tech);
    ok('core: grep.app, blocked (bot protection), scan done', r.sources && r.sources.grepapp && r.sources.grepapp.status === 'blocked' && s.scans.slice(-1)[0].status === 'done', r.sources);
    ok('core: secret masked only', (r.secrets || []).length === 1 && !JSON.stringify(s).includes('Q7XK2M9PLR4TZW8N'), r.secrets);
    ok('core: recon.* findings in the common list', s.findings.some(f => f.module === 'recon'));
    const act = await api('request_log_get', { project: p.id, only_active: true });
    ok('passive: no requests to the target', act.length === 0, act.slice(0, 3));
    // Data screens.
    await o.go('/p/data/tech'); await wait(400);
    let tx = await text();
    ok('"Технологии сайта": versions and "Устарело"', /jQuery/.test(tx) && /Устарело/.test(tx), tx.slice(0, 200));
    await step('e10_tech');
    await o.go('/p/data/site'); await wait(400);
    tx = await text();
    ok('"Сайт": favicon and Shodan/FOFA/Censys queries, hidden paths', /mmh3/.test(tx) && /Shodan/.test(tx) && /\/admin\//.test(tx), tx.slice(0, 200));
    await step('e10_site');
    await o.go('/p/data/js'); await wait(400);
    tx = await text();
    ok('"JS и API": endpoint and mask', /\/api\/v2\/users/.test(tx) && /AKIA…/.test(tx), tx.slice(0, 200));
    await o.go('/p/data/code'); await wait(400);
    tx = await text();
    ok('"Код": empty with reason "защита от ботов"', /защиту от ботов/.test(tx), tx.slice(0, 200));
    await step('e10_code');
    // Report.
    const rep = await api('report_build', { project: p.id, opts: { fmt: 'md', lang: 'ru', tpl: 'full' } });
    ok('report built', !!rep && !!(rep.name || rep.file || rep.id), rep);
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  t.finish();
};
