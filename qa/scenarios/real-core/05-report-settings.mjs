// E2E-05: HTML report (report_build → file in the private directory, Report.path; history preview from the snapshot), wordlist
// export (export_build: real path + saved_as → save to files), settings: API key shown only masked, proxy, PIN and lock screen.
import { harness } from './lib.mjs';
import { readFileSync } from 'node:fs';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, click, until, api, step, text, sheetText } = t;
  try {
    const pid = (await api('project_list')).find(p => p.name === 'example.test').id;
    await api('project_open', { id: pid });
    // Report.
    await o.go('/p/report-new');
    await step('e05_report_new');
    // Full HTML report through the builder.
    await ev(() => { FOCA.actions['rp-d']('tpl:full'); FOCA.actions['rp-d']('fmt:html'); });
    await wait(300);
    // After a passive scan findings are "new"; by default the report includes all except false positives, and the screen says so.
    const inc = await ev(() => (document.querySelector('.rp-incl') || {}).innerText || '');
    ok('"В отчёт войдут: N находок…" before build, N > 0', /В отчёт войдут: [1-9]\d* наход/.test(inc), inc);
    await click('rp-build');
    const built = await until(() => /Отчёт готов/.test((document.querySelector('.sheet.show') || {}).innerText || ''), null, 20000);
    ok('report built by core', built, await sheetText());
    await step('e05_report_built');
    const reps = await api('report_list', { project: pid });
    ok('Report.path: file in private data dir', reps.length && reps[0].path && reps[0].path.startsWith('/') && reps[0].path.includes('/reports/'), reps[0]);
    {
      const s0 = await api('project_snapshot', { id: pid });
      const html = readFileSync(reps[0].path, 'utf8');
      const ids = reps[0].result.finding_ids || [];
      ok('report with UI defaults contains findings (not empty)', ids.length > 0 && ids.length === s0.findings.filter(f => f.status !== 'false' && f.status !== 'fixed').length, { ids: ids.length, opts: reps[0].opts });
      const f0 = s0.findings.find(f => ids.includes(f.id));
      const has = v => !v || html.includes(String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'));
      // The default report language is UA, so the finding title is translated by rule; look for its parameter.
      const fArg = f0 && ((f0.title.match(/\(([^)]+)\)/) || [])[1] || f0.title);
      ok('report file contains a (translated) finding, document, person, host', f0 && has(fArg) && has((s0.docs[0] || {}).name) && has((s0.people[0] || {}).name) && has((s0.hosts[0] || {}).name), f0 && f0.title);
    }
    await ev(() => FOCA.closeSheet()); await wait(300);
    // A report from history uses its snapshot: marking a finding false afterwards does not change the preview.
    const snap = await api('project_snapshot', { id: pid });
    const live = snap.findings.find(f => f.status === 'new' && reps[0].result.finding_ids.includes(f.id));
    if (live) await api('finding_set_status', { project: pid, id: live.id, status: 'false' });
    await o.go('/p/reports');
    await step('e05_reports');
    await ev(id => FOCA.actions['rp-open'](String(id)), reps[0].id); await wait(800);
    const pv = await text();
    ok('preview from history: from report snapshot', !live || pv.includes(live.title.slice(0, 30)) || /снимок|сформирован/i.test(pv), pv.slice(0, 160));
    await step('e05_report_preview');
    if (live) await api('finding_set_status', { project: pid, id: live.id, status: 'new' });
    // Sharing a report from history: the file is found by report id.
    const sh = await api('platform_share', { project: pid, report: reps[0].id });
    ok('platform_share {report} finds the report file', sh.ok === true, sh);
    // Wordlist export.
    await o.go('/p/data/people');
    await ev(() => FOCA.actions['dt-dict'] ? FOCA.actions['dt-dict']('people') : null); await wait(500);
    ok('wordlist export sheet', /Словарь/.test(await sheetText()), (await sheetText()).slice(0, 100));
    await step('e05_dict_sheet');
    await click('rp-ex-save', { within: '.sheet.show' }); await wait(1200);
    const sn = await t.snack();
    ok('"Сохранить в файлы": Download/FOCA-rs/<name> from platform_save', /Сохранено: Download\/FOCA-rs\/.+/.test(sn), sn);
    const x = await api('export_build', { project: pid, kind: 'users', fmt: 'dict', opts: {} });
    ok('export_build: private path, saved_as for display', x.path.startsWith('/') && x.saved_as === 'Download/FOCA-rs/' + x.name, x);
    // Settings: API key.
    await o.go('/settings/keys');
    await ev(() => FOCA.actions['st-key']('brave')); await wait(400);
    await ev(() => { document.getElementById('st-kv').value = 'BSAqTEST1234567890ab12'; });
    await click('st-ksave:brave', { within: '.sheet.show' }); await wait(800);
    const st = await api('settings_get');
    ok('key: core returned only a mask', st.keys.brave.status === 'ok' && st.keys.brave.mask && !JSON.stringify(st).includes('BSAqTEST1234567890ab12'), st.keys.brave);
    const kt = await text();
    ok('keys screen: mask, not value', !kt.includes('BSAqTEST1234567890ab12'), kt.slice(0, 200));
    // Saving again without changes does not overwrite the key with its mask.
    await ev(() => FOCA.actions['st-key']('brave')); await wait(300);
    await click('st-ksave:brave', { within: '.sheet.show' }); await wait(600);
    ok('re-saving the mask does not change the key', (await api('settings_get')).keys.brave.mask === st.keys.brave.mask);
    await step('e05_keys');
    await api('key_delete', { service: 'brave' });
    // Proxy.
    await o.go('/settings/network');
    await step('e05_network');
    await api('settings_set', { patch: { net: { proxy_on: true, type: 'socks5', addr: '127.0.0.1:9050' } } });
    await o.go('/settings/network');
    const pa = await ev(() => (document.querySelector('#st-paddr') || {}).value || document.querySelector('.page').innerText);
    ok('proxy: address from core shown on screen', /127\.0\.0\.1:9050/.test(pa), pa.slice(0, 120));
    await step('e05_network_proxy');
    await api('settings_set', { patch: { net: { proxy_on: false } } });
    // PIN and lock screen.
    await o.go('/lock');
    ok('PIN not set → screen offers to set it', /новый PIN/i.test(await ev(() => document.querySelector('.st-lock').innerText)));
    ok('no demo PIN hint', !/1234/.test(await ev(() => document.querySelector('.st-lock').innerText)));
    await step('e05_lock_set');
    for (const d of '2580') await ev(x => FOCA.actions['st-lk'](x), d);
    await wait(300);
    for (const d of '2580') await ev(x => FOCA.actions['st-lk'](x), d);
    await wait(1200);
    ok('PIN set in core (pin_set)', (await api('settings_get')).sec.pin_set === true);
    await o.go('/lock');
    for (const d of '1111') await ev(x => FOCA.actions['st-lk'](x), d);
    ok('wrong PIN: attempts left (pin_check)', await until(() => /осталось попыток: 4/.test((document.querySelector('.st-lock') || {}).innerText || ''), null, 15000));
    await step('e05_lock_bad');
    for (const d of '2580') await ev(x => FOCA.actions['st-lk'](x), d);
    ok('correct PIN: unlocked', await until(() => FOCA.current() !== '/lock', null, 15000), await t.route());
  } catch (e) { ok('scenario without exceptions', false, String(e.stack || e)); }
  t.finish();
};
