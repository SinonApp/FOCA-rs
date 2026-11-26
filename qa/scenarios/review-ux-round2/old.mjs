// Re-checks older items 4, 6, 7, 8, 9, 17, 18, 19, 20 with clicks.
import { mk } from './lib.mjs';
export default async (page, ctx) => {
  const h = mk(page, ctx, 'old'); const { tap, type, back, shot, ev, note, wait } = h;
  const acts = () => ev(() => [...document.querySelectorAll('#tb-acts [aria-label]')].map(b => b.getAttribute('aria-label')));
  const G = async r => { await h.go('/projects'); await ev(r => FOCA.reset(r.startsWith('/p/') && r !== '/p/overview' ? ['/projects', '/p/overview', r] : r.startsWith('/settings/') ? ['/projects', '/settings', r] : r === '/new' ? ['/projects', '/p/overview', r] : ['/projects', r]), r); await wait(400); };
  try {
    // #4 search: open a result → Back → the query is kept; recent queries.
    await G('/p/findings');
    await tap('#searchpill', 'search');
    await type('#gq', 'Jenkins'); await wait(300);
    await tap(page.locator('#gres [data-act^="gopen"]').first(), 'result');
    note('#4 opened', await h.cur());
    await back(); note('#4 after back', await h.cur(), await ev(() => ({ q: document.querySelector('#gq')?.value, res: document.querySelector('#gres')?.innerText.slice(0, 80) })));
    await type('#gq', ''); await wait(200); note('#4 recent', await ev(() => document.querySelector('#gres')?.innerText.slice(0, 120)));
    await shot('search_recent');
    // #6 tapping the active tab again.
    await G('/p/overview');
    await ev(() => { document.querySelector('.page').scrollTop = 400; }); await wait(200);
    await tap(page.locator('#nav').getByText('Обзор', { exact: true }), 'Overview again');
    await wait(600); note('#6 scrollTop after retap', await ev(() => document.querySelector('.page').scrollTop));
    // #7 add to report → builder.
    await G('/p/finding/4');
    await tap('#tb-acts [aria-label="Ещё"]', '⋮');
    note('#7 menu', await ev(() => [...document.querySelectorAll('.sheet.show .srow')].map(e => e.innerText.split('\n')[0])));
    await tap(page.locator('.sheet.show [data-act^="fd-to-report"]'), 'To report');
    await G('/p/report-new');
    note('#7 picked row', await ev(() => [...document.querySelectorAll('.rp-opts .t, .rp-opts .lbl, .rp-opts')].map(e => e.innerText.replace(/\s+/g, ' ')).slice(0, 2)));
    // #8 switching the template keeps minSev; re-entering.
    await tap('[data-act="rp-d:minSev:high"]', 'High+');
    await tap('[data-act="rp-d:tpl:brief"]', 'Summary');
    note('#8 after tpl', await ev(() => document.querySelector('[data-act^="rp-d:minSev"].on')?.textContent));
    await tap('[data-act="rp-d:tpl:full"]', 'Full');
    await back(); await tap('#fab', 'FAB');
    note('#8 reenter', await h.cur(), await ev(() => document.querySelector('[data-act^="rp-d:minSev"].on')?.textContent));
    // #9 E-mail → wordlist export.
    await G('/p/data/emails');
    await tap('[data-act="dt-mail-export"]', 'Wordlist export');
    note('#9 sheet', await ev(() => ({ on: document.querySelector('.sheet.show [data-act^="rp-ex-dict"].on, .sheet.show [data-act^="rp-ex-dict"][aria-pressed="true"], .sheet.show [data-act^="rp-ex-dict"][aria-checked="true"]')?.innerText, head: document.querySelector('.sheet.show')?.innerText.slice(0, 120) })));
    await shot('emails_dict');
    // #17 key in settings: the eye toggle.
    await G('/settings/keys');
    await tap(page.locator('.page [data-act^="st-key"]').first(), 'key');
    note('#17 key sheet', await ev(() => document.querySelector('.sheet.show')?.innerText.slice(0, 120)));
    const eye = page.locator('.sheet.show [aria-label*="оказ"]').first();
    await tap(eye, 'eye');
    await shot('key_eye');
    note('#17 after eye', await ev(() => ({ type: document.querySelector('#st-kv')?.type, finger: !!document.querySelector('.st-finger') })));
    // #18 deleting an exclusion in the wizard: undo.
    await G('/new');
    await tap('[data-act="la-adv"]', 'Advanced');
    await type('#la-excl', '10.0.0.9'); await tap('[data-act="la-excl-add"]');
    await tap(page.locator('[data-act^="la-excl-del"]').first(), 'delete exclusion');
    note('#18 snack', await ev(() => document.querySelector('#snack.show')?.innerText));
    // #19 multi-select: header button on findings and documents.
    await G('/p/findings'); note('#19 findings acts', await acts());
    await G('/p/data/docs'); note('#19 docs acts', await acts());
    // fd-sel-many from a card: does Back repeat screens?
    await G('/p/findings'); await tap(page.locator('.page .fd-card').first(), 'card');
    await tap('#tb-acts [aria-label="Ещё"]', '⋮'); await tap(page.locator('.sheet.show [data-act^="fd-sel-many"]'), 'Select multiple');
    note('#19 sel', await h.cur());
    await back('exit selection'); note('#19 b1', await h.cur());
    await back(); note('#19 b2', await h.cur());
    await back(); note('#19 b3', await h.cur());
    // #20 kill switch texts.
    await G('/settings/network');
    note('#20 settings', await ev(() => [...document.querySelectorAll('.page .row')].map(r => r.innerText.replace(/\s+/g, ' ')).filter(t => /Kill/.test(t))));
    // #16 kill switch off: sheet.
    await tap(page.locator('.page .row').filter({ hasText: 'Kill switch' }).first(), 'kill switch row');
    note('#16 sheet', await ev(() => document.querySelector('.sheet.show')?.innerText.replace(/\s+/g, ' ').slice(0, 200)));
    await shot('kill_sheet');
  } catch (e) { note('ERR', e.message.split('\n')[0]); }
  console.log('OLD', JSON.stringify({ log: h.log }));
};
