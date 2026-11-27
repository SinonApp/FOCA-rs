// E2E-13: the built-in reference case on the real core, driven through the UI. «Открыть эталонный кейс» on the
// projects screen → import progress → the new project opens; then the graph, network map, timeline and heat map,
// standards chips in a finding card, preflight hygiene with cleaning of one file (before/after), and a report on the
// laboratory-work template built from the report builder and opened in the preview. Every screen is checked for
// undefined/NaN/null/[object Object]; the request journal of the project stays empty (no network at all).
import fs from 'fs';
import { harness } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, until, api, click, step, route, text } = t;
  try {
    const tg = await api('terms_get');
    if (!tg.accepted) { await api('terms_accept', { version: tg.version }); await ev(() => location.reload()); await wait(1200); }
    await ev(() => { try { localStorage.setItem('foca-welcomed', '1'); } catch (e) {} });
    // 1) Import from the projects screen.
    await o.go('/projects'); await wait(500);
    const before = (await api('project_list')).map(p => p.id);
    // A leftover reference project from an earlier run would turn the tap into the «уже есть» sheet.
    for (const p of await api('project_list')) if (p.name === 'Эталонный кейс') await api('project_delete', { id: p.id });
    await o.go('/projects'); await wait(400);
    await click('demo-case', { within: '.pj-offline' });
    const r0 = await route();
    ok('reference case: the import screen shows the progress', r0 === '/import' || r0 === '/p/overview', r0);
    ok('reference case: the new project opens', await until(() => FOCA.current() === '/p/overview' && FOCA.db.project && FOCA.db.project.name === 'Эталонный кейс', null, 60000), await route());
    await wait(800);
    const pid = await t.project();
    // A page load reopens the last ordinary project, never a reference case, so stay in the page from here on.
    const nav = r => ev(x => FOCA.go(x), r);
    ok('reference case: a new project id', !!pid && !before.includes(pid), pid);
    const s = await api('project_snapshot', { id: pid });
    ok('reference case: documents analysed, findings present, no scan', s.docs.length >= 12 && s.findings.length > 5 && !s.scans.some(x => x.status === 'running'), [s.docs.length, s.findings.length]);
    await step('refcase_overview');
    // 2) Graph, network map, timeline and heat map.
    await nav('/p/graph'); await wait(900);
    ok('graph: layered nodes drawn', await until(() => document.querySelectorAll('.ins-n').length > 3, null, 15000), await ev(() => document.querySelectorAll('.ins-n').length));
    await step('refcase_graph');
    await nav('/p/netmap'); await wait(900);
    ok('network map: nodes from the documents', await until(() => document.querySelectorAll('.ins-nm-r').length > 1, null, 15000), (await text()).slice(0, 200));
    await step('refcase_netmap');
    await nav('/p/timeline'); await wait(900);
    ok('timeline: year lanes and the 7×24 heat map', await until(() => document.querySelectorAll('.ins-hg i').length === 168 && document.querySelectorAll('.ins-ln-r').length > 0, null, 15000), await ev(() => [document.querySelectorAll('.ins-hg i').length, document.querySelectorAll('.ins-ln-r').length]));
    await step('refcase_timeline');
    // 3) Standards in a finding card.
    const fs1 = s.findings.find(f => f.standards && (f.standards.cwe.length || f.standards.mitre.length));
    ok('snapshot: findings carry standards from the core', !!fs1, s.findings.map(f => (f.provenance || {}).rule).slice(0, 20));
    if (fs1) {
      await nav(`/p/finding/${fs1.id}`); await wait(700);
      const chips = await ev(() => [...document.querySelectorAll('.fd-stdc')].map(x => x.textContent));
      ok('finding card: standards chips', chips.length > 0 && chips.some(c => /^(ATT&CK T\d{4}|CWE-\d+)/.test(c)), chips);
      await step('refcase_finding_standards');
    }
    // 4) Preflight hygiene and cleaning one file.
    const ids = s.docs.filter(d => !d.deleted).map(d => d.id);
    await ev(f => { FOCA.state.v2.pf = { step: 1, files: f, cleaned: [] }; FOCA.go('/p/preflight'); }, ids);
    ok('preflight: set grade and per-file grades', await until(() => /Гигиена набора/.test(document.querySelector('.page').innerText) && document.querySelectorAll('.v2pf-fh .hy-g').length > 0, null, 20000), (await text()).slice(0, 200));
    await step('refcase_preflight');
    const jpg = s.docs.find(d => /\.(jpe?g|odt)$/i.test(d.name)) || s.docs[0];
    await click(`v2pf-clean:${jpg.id}`);
    ok('cleaning: before/after screen with the verdict', await until(() => FOCA.current() === '/clean/result' && /было/.test(document.querySelector('.page').innerText), null, 30000), (await text()).slice(0, 300));
    await step('refcase_before_after');
    // 5) Laboratory-work report from the builder.
    const nRep = s.reports.length;
    await nav('/p/report-new'); await wait(700);
    await click('rp-d:tpl:lab'); await wait(600);
    ok('report builder: core description of the laboratory work', /Лабораторн/.test(await text()) && !(await ev(() => !!document.querySelector('.rp-secs'))), (await text()).slice(0, 300));
    await click('rp-d:fmt:html'); await wait(300);
    await step('refcase_report_builder');
    await click('rp-build');
    ok('report: built', await until(n => FOCA.db.reports.length > n && !!document.querySelector('.sheet.show [data-act="rp-b-open"]'), nRep, 60000), await ev(() => FOCA.db.reports.length));
    const rs = (await api('project_snapshot', { id: pid })).reports;
    const rep = rs[0] || {};
    ok('report: template lab stored with the report', rep.opts && rep.opts.tpl_id === 'lab', rep.opts);
    const html = rep.path && fs.existsSync(rep.path) ? fs.readFileSync(rep.path, 'utf8') : '';
    const body = html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/g, '').replace(/<[^>]+>/g, ' ');
    ok('report: laboratory-work sections and the standards table', /Лабораторна робота|Лабораторная работа|Laboratory work/.test(body) && /CWE-\d+|T\d{4}/.test(body), body.length);
    ok('report: no undefined/NaN/null/[object Object] in the text', !/\b(undefined|NaN|null|\[object Object\])\b/.test(body), (body.match(/.{0,40}\b(undefined|NaN|null|\[object Object\])\b.{0,40}/) || [''])[0]);
    await click('rp-b-open', { within: '.sheet.show' }); await wait(800);
    ok('report preview: laboratory-work outline', (await route()) === '/p/report-preview' && /Лаборатор/.test(await text()), await route());
    await step('refcase_report_preview');
    // 6) Nothing went to the network.
    const log = await api('request_log_get', { project: pid, limit: 5000 });
    ok('request journal of the reference case is empty', Array.isArray(log) && log.length === 0, log.slice(0, 3));
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  t.finish();
};
