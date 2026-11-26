// Flows 3 (repeat), 5, 6, 7.
import { mk } from './lib.mjs';
export default async (page, ctx) => {
  const h = mk(page, ctx, 's3'); const { tap, type, hold, back, shot, ev, note, wait } = h;
  const R = {};
  const nav = t => tap(page.locator('#nav').getByText(t, { exact: true }), 'tab ' + t);
  const txt = () => ev(() => (document.querySelector('.sheet.show') || document.querySelector('.page'))?.innerText.replace(/\s+/g, ' ').slice(0, 350));
  try {
    if (!process.env.ONLY67) {
    // 3. Person → login wordlist.
    await h.go('/p/overview'); h.reset();
    await nav('Данные');
    await tap(page.locator('.page').getByText('Люди', { exact: false }).first(), 'People');
    await tap(page.locator('.page [data-act*="/p/entity/person/"]').first(), 'person');
    await tap('.page [data-act^="dt-dict:"]', 'Login wordlist');
    await shot('person_dict');
    note('dict-sheet', await txt());
    const sh = page.locator('.sheet.show [data-act]').filter({ hasText: /Поделиться|Экспорт|Сохранить/ }).last();
    note('dict-btns', await ev(() => [...document.querySelectorAll('.sheet.show [data-act]')].map(b => b.textContent.trim().slice(0, 30) + '|' + b.dataset.act)));
    await tap(sh, 'Share');
    await shot('person_dict_share');
    note('after', await h.cur(), await txt());
    const app = page.locator('.sheet.show [data-act]').filter({ hasText: /Signal|Файлы/ }).first();
    if (await app.count()) await tap(app, 'app');
    R.dict = h.reset();

    // 5. Scan running → leave/return; network; VPN.
    await h.go('/p/overview'); h.reset();
    await tap('#fab', 'FAB New scan');
    await tap('[data-act="la-prof:passive"]', 'Passive');
    await tap('#la-start', 'Start scan');
    note('started', await h.cur(), await ev(() => FOCA.scan.running));
    await nav('Находки');
    await tap(page.locator('.page .fd-card').first(), 'card');
    await shot('mini_on_finding');
    note('mini', await ev(() => { const m = document.querySelector('#mini'); const r = m.getBoundingClientRect(); const f = document.querySelector('.fd-foot')?.getBoundingClientRect(); const n = document.querySelector('#nav').getBoundingClientRect(); return { show: m.classList.contains('show'), mini: [Math.round(r.top), Math.round(r.bottom)], foot: f && [Math.round(f.top), Math.round(f.bottom)], nav: [Math.round(n.top), Math.round(n.bottom)] }; }));
    await tap('#mini', 'mini-panel');
    note('mini->', await h.cur());
    await back(); note('back from scan', await h.cur());
    // Network loss.
    await ev(() => FOCA.setOffline(true)); await wait(400);
    await shot('offline_finding');
    note('offline', await ev(() => ({ mini: document.querySelector('#mi-t')?.textContent + ' / ' + document.querySelector('#mi-s')?.textContent, banner: document.querySelector('#offline')?.innerText, paused: FOCA.scan.paused, reason: FOCA.scan.pauseReason })));
    await tap('#mi-pp', 'mini-panel button (resume?)');
    note('mi-pp offline', await ev(() => ({ paused: FOCA.scan.paused, snack: document.querySelector('#snack.show')?.innerText })));
    await tap('#mini', 'mini-panel'); await shot('offline_scan');
    note('scan-offline', await txt());
    await ev(() => FOCA.setOffline(false)); await wait(500);
    note('online', await ev(() => ({ paused: FOCA.scan.paused, snack: document.querySelector('#snack.show')?.innerText })));
    await ev(() => FOCA.scanDemo.ff(200)); await wait(500);
    R.scanNet = h.reset();
    // Deep link /p/scan (notification) → Back.
    await h.go('/p/scan'); h.reset();
    note('deeplink', await h.cur(), await ev(() => getComputedStyle(document.querySelector('#tb-back')).display));
    await tap('#tb-back', 'arrow'); note('deeplink-back', await h.cur());
    await h.go('/p/scan-stopped/vpn'); h.reset();
    await shot('vpn_deeplink');
    note('vpn-dl', await txt());
    await h.tbBack(); note('vpn-dl-back', await h.cur());

    }
    // 6. API key and proxy from the wizard.
    await h.go('/projects'); h.reset();
    await type('#pj-q', 'acme.ua'); await tap('.pj-go', '→');
    await type('#la-pclient', 'ACME', 'client');
    await tap('[data-act="la-adv"]', 'Advanced');
    await shot('adv');
    note('src', await ev(() => [...document.querySelectorAll('.la-src')].map(r => r.innerText.replace(/\s+/g, ' ')).slice(0, 12)));
    await tap('[data-act="la-key:censys"]', 'Specify Censys');
    await shot('key_sheet');
    note('key-sheet', await h.cur(), await txt());
    const kin = page.locator('.sheet.show input').first();
    if (await kin.count()) { await kin.fill('cs_live_1234567890abcdef'); h.note('type'); }
    const save = page.locator('.sheet.show [data-act]').filter({ hasText: /Сохранить|Проверить/ }).last();
    await tap(save, 'Save key');
    await wait(800);
    await shot('after_key');
    note('after-key', await h.cur(), await txt());
    // Possibly a fingerprint prompt.
    const fp = page.locator('.sheet.show [data-act]').filter({ hasText: /отпечат|Подтвердить/i }).first();
    if (await fp.count()) { await tap(fp, 'fingerprint'); await wait(800); note('after-fp', await h.cur(), await txt()); }
    note('censys-status', await ev(() => [...document.querySelectorAll('.la-src')].map(r => r.innerText.replace(/\s+/g, ' ')).filter(x => /Censys/.test(x))));
    note('wizard-kept', await ev(() => ({ client: document.querySelector('#la-pclient')?.value, t: FOCA.state.launch.targets.map(t => t.v) })));
    // Proxy.
    await tap('[data-act="la-netcheck"]', 'Check proxy');
    await wait(800);
    note('netcheck', await ev(() => document.querySelector('.la-netb')?.parentElement?.innerText.replace(/\s+/g, ' ').slice(0, 300)));
    await shot('netcheck');
    await tap('.la-netb [data-act="go:/settings/network"]', 'Edit proxy');
    await shot('settings_network');
    note('net', await h.cur());
    await back('Back to wizard'); note('back-to-wizard', await h.cur(), await ev(() => ({ client: document.querySelector('#la-pclient')?.value, adv: FOCA.state.launch.adv })));
    R.keyProxy = h.reset();
    // New project wizard: is the input lost on system Back?
    await type('#la-in', '10.1.1.0/24'); await tap('[data-act="la-commit"]');
    const before = await ev(() => ({ t: FOCA.state.launch.targets.map(t => t.v), client: FOCA.state.launch.pclient }));
    await back('Back from wizard'); note('wizard-back', await h.cur(), await ev(() => ({ sheet: document.querySelector('.sheet.show')?.innerText, snack: document.querySelector('#snack.show')?.innerText })));
    await shot('wizard_back');
    await tap('.pj-go', '→ again (empty field)');
    const after = await ev(() => ({ r: FOCA.current(), t: FOCA.state.launch.targets.map(t => t.v), client: FOCA.state.launch.pclient }));
    note('wizard-lost', { before, after });
    await shot('wizard_reopen');

    // 7. Search.
    await h.go('/p/findings'); h.reset();
    await shot('findings_pill');
    note('pill', await ev(() => { const p = document.querySelector('#searchpill'); const r = p.getBoundingClientRect(); return { t: p.innerText, top: r.top, h: r.height }; }));
    await tap('#searchpill', 'search');
    note('search-open', await h.cur(), await ev(() => ({ chip: document.querySelector('#gchips .on')?.textContent, focus: document.activeElement?.id })));
    await type('#gq', 'TLS', 'query');
    await wait(400); await shot('search_tls');
    note('res-tls', await ev(() => document.querySelector('#gres')?.innerText.replace(/\s+/g, ' ').slice(0, 300)));
    await tap('[data-act="gchip:all"], #gchips button', 'All chip', {});
    await type('#gq', 'info@');
    await wait(300); note('res-mail', await ev(() => document.querySelector('#gres')?.innerText.replace(/\s+/g, ' ').slice(0, 200)));
    await type('#gq', 'Бондар'); await wait(300);
    await shot('search_bondar');
    note('res-b', await ev(() => document.querySelector('#gres')?.innerText.replace(/\s+/g, ' ').slice(0, 200)));
    await tap(page.locator('#gres [data-act]').first(), 'result');
    note('opened', await h.cur());
    await back(); note('back-search', await h.cur(), await ev(() => document.querySelector('#gq')?.value));
    await shot('search_after_back');
    R.search = h.reset();
  } catch (e) { note('ERR', e.message.split('\n')[0]); }
  console.log('s3', JSON.stringify({ R, log: h.log }, null, 0));
};
