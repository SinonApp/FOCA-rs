// E2E-03: triage on the real core: findings (confirm/false positive → overview numbers and project_list), data (all segments,
// document/person/host cards, graph, map, timeline), secret (secret_reveal after confirmation), document delete/restore,
// sharing a document and a finding, photo evidence, adding own files, pre-publication check.
import { harness } from './lib.mjs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, click, until, api, step, text } = t;
  try {
    const pid = (await api('project_list'))[0].id;
    await api('project_open', { id: pid });
    let snap = await api('project_snapshot', { id: pid });
    const openN = s => s.findings.filter(f => !['false', 'fixed'].includes(f.status)).length;
    // Findings.
    await o.go('/p/findings');
    const n0 = await ev(() => document.querySelectorAll('.page [data-fid], .page .fd-row, .page .fd-card').length);
    ok('findings list not empty', n0 > 0, n0);
    await step('e03_findings');
    const f1 = snap.findings.find(f => f.status === 'new' && f.sev !== 'info'), f2 = snap.findings.filter(f => f.status === 'new' && f.id !== f1.id)[0];
    const risk0 = (await api('project_list')).find(p => p.id === pid).risk;
    await o.go('/p/finding/' + f1.id);
    await step('e03_finding');
    await click(`fd-set:${f1.id}:confirmed`); await wait(500);
    await o.go('/p/finding/' + f2.id);
    await click(`fd-set:${f2.id}:false`); await wait(500);
    snap = await api('project_snapshot', { id: pid });
    ok('core: finding statuses saved', snap.findings.find(f => f.id === f1.id).status === 'confirmed' && snap.findings.find(f => f.id === f2.id).status === 'false');
    await o.go('/p/overview');
    const c = await ev(() => FOCA.sel.counts());
    ok('Overview: open findings = core after "false positive"', c.findings.open === openN(snap), { ui: c.findings.open, core: openN(snap) });
    ok('Overview: confirmed = 1', c.findings.confirmed === 1, c.findings.confirmed);
    const pl = (await api('project_list')).find(p => p.id === pid);
    ok('project_list: findings exclude false positives', pl.findings === openN(snap), pl);
    ok('risk recomputed by core', pl.risk <= risk0, { before: risk0, after: pl.risk });
    // Share a finding and a photo.
    await o.go('/p/finding/' + f1.id);
    await ev(id => FOCA.actions['fd-share'](String(id)), f1.id); await wait(900);
    ok('finding "Поделиться карточкой": export_build md → platform_share', /Отправка: .*\.md/.test(await t.snack()), await t.snack());
    await ev(id => FOCA.actions['fd-photo'](`${id}:gal`), f1.id); await wait(1200);
    snap = await api('project_snapshot', { id: pid });
    const ph = snap.findings.find(f => f.id === f1.id).photos;
    ok('photo evidence: picked file attached', ph.length === 1 && /\.jpg$/i.test(ph[0].name), ph);
    await step('e03_finding_photo');
    // Data: all segments.
    for (const seg of ['docs', 'people', 'emails', 'hosts', 'software', 'secrets', 'paths', 'printers']) {
      await o.go('/p/data/' + seg);
      const tx = await text();
      ok(`Данные/${seg}: screen without "undefined"`, !/undefined|NaN/.test(tx), tx.slice(0, 120));
      await step('e03_data_' + seg);
    }
    // Cards.
    const doc = snap.docs.find(d => d.status === 'analyzed' && d.author);
    await o.go('/p/doc/' + doc.id);
    const dt = await text();
    ok('document card: name, author and real SHA-256', dt.includes(doc.name) && dt.includes(doc.sha256.slice(0, 12)), dt.slice(0, 200));
    await step('e03_doc');
    await ev(id => FOCA.actions['dd-share-do'](`file:${id}`), doc.id); await wait(800);
    ok('"Поделиться" document file (doc_file → platform_share)', /Отправка: /.test(await t.snack()), await t.snack());
    const person = snap.people[0], host = snap.hosts.find(h => !h.internal) || snap.hosts[0];
    await o.go('/p/entity/person/' + encodeURIComponent(person.login)); await step('e03_person');
    ok('person card', (await text()).includes(person.name));
    await o.go('/p/entity/host/' + encodeURIComponent(host.name)); await step('e03_host');
    ok('host card', (await text()).includes(host.name));
    await o.go('/p/graph/person/' + encodeURIComponent(person.login)); await step('e03_graph');
    ok('graph: has nodes', await ev(() => document.querySelectorAll('.page svg circle, .page svg g').length > 1));
    await o.go('/p/map'); await step('e03_map');
    // The 3D globe covers the whole world: a point outside Ukraine is visible and its country is among the panel chips.
    for (let i = 0; i < 20 && !(await ev(() => document.querySelectorAll('#v2m-panel .v2m-chips .chip').length > 1)); i++) await new Promise(r => setTimeout(r, 150));
    const mp = await ev(() => document.querySelector('#v2m-panel')?.textContent || '');
    ok('map: globe drawn, point outside Ukraine, own country in panel', await ev(() => !!document.querySelector('#v2m-cv')) && (snap.gps.some(g => g.lon < 22) ? /Великобритания|Германия|Польша|Франция|США/.test(mp) || (mp.match(/\d+/g) || []).length > 3 : true), mp.slice(0, 200));
    await o.go('/p/timeline'); await step('e03_timeline');
    // Secret.
    await o.go('/p/data/secrets');
    const sec = snap.secrets[0];
    const before = await ev(() => document.querySelector('.page').innerText);
    await ev(id => FOCA.actions['dt-sec-show'](String(id)), sec.id); await wait(900);
    const rv = await api('secret_reveal', { project: pid, id: sec.id });
    const after = await ev(() => document.querySelector('.page').innerText);
    ok('secret: masked before confirmation, value from secret_reveal after', !before.includes(rv.value) && after.includes(rv.value), { mask: sec.mask });
    await step('e03_secret');
    // Delete / restore a document.
    const d0 = snap.docs.filter(d => !d.deleted).length;
    await o.go('/p/doc/' + doc.id);
    await ev(id => FOCA.actions['dd-del'](String(id)), doc.id); await wait(900);
    snap = await api('project_snapshot', { id: pid });
    ok('document deletion: core', snap.docs.filter(d => !d.deleted).length === d0 - 1);
    await o.go('/p/overview');
    ok('Overview: one document fewer', await ev(() => FOCA.sel.counts().docs.total) === d0 - 1);
    await api('doc_restore', { project: pid, ids: [doc.id] });
    await o.go('/p/overview');
    ok('restore: counts are back', await ev(() => FOCA.sel.counts().docs.total) === d0);
    // Own files.
    await o.go('/p/data/docs');
    ok('Documents: "Добавить свои файлы" button', await ev(() => !!document.querySelector('[data-act="dd-import"]')));
    await click('dd-import'); await wait(2500);
    const s2 = await api('project_snapshot', { id: pid });
    ok('own files imported (doc_import)', s2.docs.length > snap.docs.length, { before: snap.docs.length, after: s2.docs.length });
    await step('e03_import');
    await o.go('/p/preflight');
    await click('v2pf-pick'); await wait(2500);
    const pf = await text();
    ok('pre-publication check on real files', /Что утечёт/.test(pf), pf.slice(0, 160));
    await step('e03_preflight');
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  t.finish();
};
