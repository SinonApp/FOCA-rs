// E2E-07: the Debug tab on the real core: the core log is visible after a scan (level/source filters, search),
// project requests with access type and a target-only filter, crashes, device; "share logs" → ZIP without secrets
// (the stored API key, a password in a URL), log level changed on the fly, "clear logs" with confirmation.
import { harness } from './lib.mjs';
import { execFileSync } from 'node:child_process';
export default async (page, o) => {
  const t = harness(page, o); const { ok, ev, wait, click, until, api, step, text } = t;
  try {
    const pid = (await api('project_list')).find(p => p.name === 'example.test').id;
    await api('project_open', { id: pid });
    const KEY = 'BSAqE2Esecret7731zz';
    await api('key_set', { service: 'brave', value: KEY });
    // Log.
    await o.go('/settings/debug');
    ok('"Отладка" route', await t.route() === '/settings/debug');
    await until(() => document.querySelectorAll('.dbg-l').length > 0, null, 10000);
    const n0 = await ev(() => document.querySelectorAll('.dbg-l').length);
    ok('core log visible after scan', n0 > 0 && /foca::scan/.test(await text()), n0);
    await step('e07_log');
    await click('dbg-lv:info'); await click('dbg-lv:debug'); await wait(200);
    const onlyBad = await ev(() => [...document.querySelectorAll('.dbg-lv')].every(e => /ERRO|WARN/.test(e.textContent)));
    ok('level chips: errors and warnings only', onlyBad);
    await click('dbg-lv:info'); await wait(150);
    await ev(() => { const i = document.querySelector('#dbg-q'); i.value = 'этап'; i.dispatchEvent(new Event('input')); }); await wait(500);
    ok('log search', await ev(() => [...document.querySelectorAll('.dbg-m')].every(e => /этап/i.test(e.closest('.dbg-l').innerText))));
    await ev(() => { const i = document.querySelector('#dbg-q'); i.value = ''; i.dispatchEvent(new Event('input')); }); await wait(400);
    // Requests.
    await click('dbg-seg:req'); await until(() => document.querySelectorAll('.dbg-r').length > 0, null, 10000);
    ok('project requests: method, host, code, access type', await ev(() => document.querySelectorAll('.dbg-r').length > 0 && /Пассивный|Касание цели/.test(document.querySelector('.dbg-req').innerText)));
    await step('e07_requests');
    await click('dbg-only'); await wait(800);
    ok('"Только к цели" filter: no passive ones', await ev(() => !/Пассивный/.test((document.querySelector('.dbg-req') || document.body).innerText)));
    // Crashes and device.
    await click('dbg-seg:crash'); await wait(600);
    ok('crashes: list or "Сбоев нет"', /Сбоев нет|crash-/.test(await text()));
    await click('dbg-seg:dev'); await until(() => /Версия/.test(document.querySelector('.page').innerText), null, 8000);
    ok('device: version, Android, memory', /Версия/.test(await text()) && /Android/.test(await text()) && /Память/.test(await text()));
    await step('e07_device');
    // Export without secrets.
    await click('dbg-share'); await wait(1200);
    ok('"Поделиться логами": archive snackbar', /Журналы собраны/.test(await t.snack()), await t.snack());
    const x = await api('logs_export', { device: 'e2e ' + KEY });
    const dump = execFileSync('python3', ['-c', 'import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);print("\\n".join(z.namelist()));[print(z.read(n).decode("utf-8","replace")) for n in z.namelist()]', x.path], { encoding: 'utf8' });
    ok('ZIP: core logs, Android and device.txt', /foca\.log/.test(dump) && /android\.log/.test(dump) && /device\.txt/.test(dump), dump.slice(0, 200));
    ok('ZIP: no API key', !dump.includes(KEY));
    // Log level and clearing.
    await click('dbg-level:debug'); await wait(400);
    ok('"Отладка" level applied in core', (await api('app_info')).log_level === 'debug');
    await click('dbg-level:info'); await wait(300);
    await click('dbg-clear'); await wait(300);
    ok('clearing requires confirmation', /Очистить логи приложения\?/.test(await t.sheetText()));
    await click('dbg-clear-go'); await wait(800);
    ok('no crash reports after clearing', (await api('crash_list')).length === 0);
    await api('key_delete', { service: 'brave' });
    // Terms under About.
    await o.go('/settings/terms');
    ok('terms read-only with acceptance date', /Приняты/.test(await text()) && !(await ev(() => !!document.querySelector('#ob-accept'))));
    await step('e07_terms_view');
  } catch (e) { ok('exception', false, String(e && e.stack || e)); }
  t.finish();
};
