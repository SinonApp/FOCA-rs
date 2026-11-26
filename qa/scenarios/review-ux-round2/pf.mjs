// /p/preflight: path from the menu, selection, cleaning, new check.
import { mk } from './lib.mjs';
export default async (page, ctx) => {
  const h = mk(page, ctx, 'pf'); const { tap, back, shot, ev, note, wait } = h;
  try {
    await h.go('/projects'); await ev(() => FOCA.reset(['/projects', '/p/overview'])); await wait(300); h.reset();
    await tap('#tb-acts [aria-label="Меню"], #tb-acts [aria-label="Ещё"]', '⋮');
    note('menu', await ev(() => [...document.querySelectorAll('.sheet.show [data-act]')].map(b => b.innerText.split('\n')[0])));
    await tap(page.locator('.sheet.show [data-act]').filter({ hasText: 'Инструменты' }).first(), 'Tools');
    await shot('tools');
    note('tools', await h.cur(), await ev(() => (document.querySelector('.sheet.show') || document.querySelector('.page')).innerText.replace(/\s+/g, ' ').slice(0, 300)));
    await tap(page.locator('[data-act]').filter({ hasText: 'Проверка перед публикацией' }).first(), 'Pre-publication check');
    await shot('pf0');
    await tap('[data-act="v2pf-pick"]', 'Pick files');
    await shot('pf_pick');
    await tap('#v2pf-ok', 'Check');
    await shot('pf1');
    note('pf1', await h.cur(), await ev(() => document.querySelector('.page').innerText.replace(/\s+/g, ' ').slice(0, 400)));
    const n1 = h.taps;
    await tap('[data-act="v2pf-clean:all"]', 'Clear all');
    await shot('pf2');
    note('taps-to-clean', n1 + 1);
    await tap('[data-act="v2pf-reset"]', 'New check');
    note('after-reset', await ev(() => ({ files: FOCA.state.v2 ? 1 : 0, txt: document.querySelector('.page').innerText.slice(0, 80), sheet: !!document.querySelector('.sheet.show'), snack: document.querySelector('#snack.show')?.innerText })));
    await shot('pf_reset');
    await back(); note('back', await h.cur());
  } catch (e) { note('ERR', e.message.split('\n')[0]); }
  console.log('PF', JSON.stringify({ log: h.log }));
};
