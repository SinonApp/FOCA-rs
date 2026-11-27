// E2E-12: insights on the real core and the offline harness. Passive profile: the web audit reads only the archived
// copy (zero requests of its own, nothing to the target), CSP hosts split into scope hosts and out-of-scope candidates.
// Standard profile: GET-only probes of the live harness site (source map, OpenAPI), no OPTIONS/TRACE. Then
// insights_get (org chart, network map, graph layers, 7×24 activity), chain_get from a document finding, and a report
// with inline SVG diagrams. Every request of the stand goes to local hosts only.
import fs from 'fs';
import { harness, DOMAIN } from './lib.mjs';
const WEB_STD = ['recon.sourcemap', 'recon.apidocs'];
const WEB_ACTIVE = ['http_options', 'http_trace', 'webdav_propfind', 'cors_origin', 'graphql_introspection'];
const local = h => !h || h === '127.0.0.1' || h === 'localhost' || h === DOMAIN || h.endsWith('.' + DOMAIN);
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, until, api } = t;
  try {
    const tg = await api('terms_get');
    if (!tg.accepted) { await api('terms_accept', { version: tg.version }); await ev(() => location.reload()); await wait(1200); }
    await ev(() => { try { localStorage.setItem('foca-welcomed', '1'); } catch (e) {} });
    await api('settings_set', { patch: { net: { rps: 0 } } });
    // 1) Passive profile.
    const p = await api('project_create', { name: 'Веб-аудит ' + DOMAIN, client: '', targets: [{ v: DOMAIN, type: 'domain' }], excludes: [] });
    await api('project_open', { id: p.id });
    await o.go('/p/overview'); await wait(300);
    await api('scan_start', { project: p.id, profile: 'passive', sources: ['wayback', 'crt', 'recon', 'webaudit'] });
    ok('passive scan finished', await until(() => !FOCA.scan.running, null, 120000), await api('scan_status'));
    await wait(600);
    let s = await api('project_snapshot', { id: p.id });
    const w = ((s.recon || {}).web || [])[0] || {};
    ok('passive: webaudit source ok', s.recon && s.recon.sources && s.recon.sources.webaudit && s.recon.sources.webaudit.status === 'ok', s.recon && s.recon.sources);
    ok('passive: audit level passive, 0 requests', w.level === 'passive' && w.requests === 0, w);
    ok('passive: CSP host in scope → hosts', (w.hosts || []).includes('api.' + DOMAIN) && s.hosts.some(h => h.name === 'api.' + DOMAIN), w.hosts);
    ok('passive: CSP host out of scope → candidate only', (w.candidates || []).includes('cdn.partner-cdn.test') && !s.hosts.some(h => h.name === 'cdn.partner-cdn.test'), w.candidates);
    const oos = await api('oos_list', { project: p.id });
    ok('passive: candidate in oos_list (csp)', oos.some(x => x.host === 'cdn.partner-cdn.test'), oos.map(x => x.host));
    const rules = s.findings.map(f => (f.provenance || {}).rule || '');
    // Headers of an archived copy belong to the archive, so a weak CSP there is not a finding about the live site;
    // the CSP host list still is.
    ok('passive: recon.web.csp_domains from the archived CSP, no header findings from the archive', rules.includes('recon.web.csp_domains') && !rules.includes('recon.web.csp_unsafe_inline'), rules.filter(r => r.startsWith('recon.web')));
    ok('insight findings: KEV / org chart / network map', rules.includes('sw.kev') && rules.includes('org.structure') && rules.includes('net.internal_map'), rules.filter(r => /^(sw\.kev|org\.|net\.|doc\.anomaly|doc\.lineage)/.test(r)));
    const kev = s.findings.filter(f => (f.provenance || {}).rule === 'sw.kev');
    ok('KEV wording: possible/likely, verify the version', kev.every(f => /сверьте версию$/.test(f.title) || /^Вероятно уязвимое ПО/.test(f.title)), kev.map(f => f.title));
    let log = await api('request_log_get', { project: p.id, limit: 5000 });
    ok('passive: no web audit requests, nothing active', !log.some(r => WEB_STD.includes(r.module) || WEB_ACTIVE.includes(r.module) || r.access !== 'passive'), log.filter(r => r.access !== 'passive').slice(0, 3));
    ok('passive: no request to the target hosts', !log.some(r => r.host === DOMAIN || (r.host || '').endsWith('.' + DOMAIN) || r.host === 'cdn.partner-cdn.test'), log.filter(r => (r.host || '').includes(DOMAIN)).slice(0, 3));
    ok('stand journal: local hosts only (passive)', log.every(r => local(r.host)), log.filter(r => !local(r.host)).slice(0, 3));
    // 2) Insights, chain, report.
    const ins = await api('insights_get', { project: p.id });
    ok('insights_get: org chart, network map, graph, timeline', ins.counts.departments > 0 && ins.netmap.nodes.length > 1 && ins.graph.nodes.length > 1 && ins.timeline.length > 0, ins.counts);
    ok('insights_get: 7×24 activity grid', ins.activity.matrix.length === 7 && ins.activity.matrix.every(r => r.length === 24) && ins.activity.total > 0, ins.activity.total);
    const lay = await api('insights_get', { project: p.id, layers: ['people', 'docs'] });
    ok('insights_get: layer filter', lay.graph.nodes.every(n => n.layer === 'people' || n.layer === 'docs') && lay.graph.hidden > 0, lay.graph.layer_counts);
    const fd = s.findings.find(f => f.doc);
    const ch = await api('chain_get', { project: p.id, from_id: fd.id });
    ok('chain_get: from a document finding', ch.start === 'doc:' + fd.doc && ch.found && Array.isArray(ch.chains), ch);
    const rep = await api('report_build', { project: p.id, opts: { fmt: 'html', lang: 'UK', min_sev: 'all', confirmed: false } });
    ok('report built (UK)', !!rep && !!rep.path, rep);
    const html = rep && rep.path ? fs.readFileSync(rep.path, 'utf8') : '';
    ok('report: inline SVG graph, network map, chronology and heat map', ['graph', 'netmap', 'timeline', 'activity'].every(id => html.includes(`id="${id}"`)) && /<svg/.test(html), html.length);
    ok('report: KEV finding translated (UK)', /CISA KEV/.test(html) && !/сверьте версию/.test(html), '');
    // 3) Standard profile on the live harness site.
    const q = await api('project_create', { name: 'Веб-аудит std ' + DOMAIN, client: '', targets: [{ v: DOMAIN, type: 'domain' }], excludes: [] });
    await api('scan_start', { project: q.id, profile: 'std', sources: ['recon', 'webaudit'] });
    ok('standard scan finished', await until(() => !FOCA.scan.running, null, 180000), await api('scan_status'));
    await wait(600);
    s = await api('project_snapshot', { id: q.id });
    const ws = ((s.recon || {}).web || [])[0] || {};
    ok('standard: site fetched directly', s.recon.sites[0] && s.recon.sites[0].via === 'site', s.recon.sites);
    ok('standard: audit level standard with requests', ws.level === 'standard' && ws.requests > 0, { level: ws.level, requests: ws.requests, errors: ws.errors });
    ok('standard: source map parsed (npm packages, local path)', (ws.source_maps || []).some(m => (m.packages || []).some(x => /axios/.test(x)) && (m.local_paths || []).length > 0), ws.source_maps);
    ok('standard: OpenAPI spec found', (ws.api_docs || []).some(d => d.kind === 'open_api' || d.kind === 'openapi'), ws.api_docs);
    const r2 = s.findings.map(f => (f.provenance || {}).rule || '');
    ok('standard: findings for headers, cookie, source map, API docs', ['recon.web.sourcemap', 'recon.web.cookie_flags', 'recon.web.hsts_missing'].some(x => r2.includes(x)) && r2.some(x => x.startsWith('recon.web.apidoc_')), r2.filter(x => x.startsWith('recon.web')));
    log = await api('request_log_get', { project: q.id, limit: 5000 });
    const webReq = log.filter(r => WEB_STD.includes(r.module));
    ok('standard: web audit requests are GET only', webReq.length > 0 && webReq.every(r => r.method === 'GET'), webReq.slice(0, 3));
    ok('standard: no OPTIONS/TRACE/PROPFIND (active only)', !log.some(r => WEB_ACTIVE.includes(r.module) || ['OPTIONS', 'TRACE', 'PROPFIND', 'PUT', 'DELETE'].includes(r.method)), log.filter(r => WEB_ACTIVE.includes(r.module)).slice(0, 3));
    ok('standard: nothing sent to out-of-scope candidates', !log.some(r => r.host === 'cdn.partner-cdn.test'));
    ok('stand journal: local hosts only (standard)', log.every(r => local(r.host)), log.filter(r => !local(r.host)).slice(0, 3));
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  t.finish();
};
