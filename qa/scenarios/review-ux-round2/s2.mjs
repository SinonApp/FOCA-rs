// Flows 2-4: triage; a person's documents → wordlist; report of confirmed high findings → share.
import { mk } from './lib.mjs';
export default async (page, ctx) => {
  const h = mk(page, ctx, 's2'); const { tap, type, hold, back, shot, ev, note, wait } = h;
  const R = {};
  const nav = t => tap(page.locator('#nav').getByText(t, { exact: true }), 'tab ' + t);
  try {
    // 2. Triage.
    await h.go('/p/overview'); h.reset();
    await nav('Находки');
    await shot('findings');
    note('first-cards', await ev(() => [...document.querySelectorAll('.page [data-act^="go:/p/finding/"], .page .fd-card')].slice(0, 3).map(e => e.textContent.trim().slice(0, 60))));
    await tap(page.locator('.page .fd-card').first(), 'first card');
    await shot('detail');
    note('foot', await ev(() => { const f = document.querySelector('.fd-foot'); if (!f) return null; const r = f.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, pos: getComputedStyle(f).position, btns: [...f.querySelectorAll('.btn')].map(b => { const q = b.getBoundingClientRect(); return b.textContent.trim() + ' ' + Math.round(q.width) + 'x' + Math.round(q.height) + '@' + Math.round(q.top); }) }; }));
    await tap('.fd-foot [data-act$=":confirmed"]', 'Confirm');
    await shot('confirmed');
    note('after-confirm', await h.cur());
    await tap(page.locator('.fd-srcdoc .row, .fd-srcdoc [data-act]').first(), 'source document');
    await shot('doc');
    note('doc', await h.cur());
    await tap(page.locator('.page [data-act*="/p/entity/person/"]').first(), 'author');
    await shot('person');
    await tap(page.locator('.page [data-act*="/p/entity/pc/"]').first(), 'PC');
    await shot('pc');
    note('crumbs', await ev(() => [...document.querySelectorAll('.page .dt-crumbs button')].map(b => b.textContent.trim() + '|' + b.dataset.act)));
    // Return to the finding with one tap on the breadcrumb.
    const crumbOk = await tap(page.locator('.page .dt-crumbs [data-act]').first(), 'finding breadcrumb');
    note('after-crumb', await h.cur());
    await shot('after_crumb');
    await tap('.fd-foot [data-act^="fd-nav:"]', 'Next (next one)');
    note('next', await h.cur());
    await shot('next');
    R.triage = h.reset();
    // Where does Back lead after the breadcrumb and "next"?
    await back(); note('back-after-next', await h.cur());
    await back(); note('back2', await h.cur());
    await back(); note('back3', await h.cur());
    h.reset();

    // 3. A person's documents → login wordlist.
    await h.go('/p/overview'); h.reset();
    await nav('Данные');
    await shot('data');
    await tap(page.locator('.page').getByText('Люди', { exact: false }).first(), 'People');
    await shot('people');
    await tap(page.locator('.page [data-act*="/p/entity/person/"]').first(), 'person');
    await shot('person2');
    note('person-actions', await ev(() => [...document.querySelectorAll('.page [data-act], #tb-acts [data-act]')].map(b => (b.textContent.trim() || b.getAttribute('aria-label') || '') + '|' + b.dataset.act).filter(x => /докум|слов|dict|export|экспорт|doc/i.test(x)).slice(0, 12)));
    const docsBtn = page.locator('.page [data-act]').filter({ hasText: /Документ/ }).first();
    await tap(docsBtn, "Person's documents");
    await shot('person_docs');
    note('docs-view', await h.cur(), await ev(() => document.querySelector('.page')?.innerText.slice(0, 200)));
    note('docs-actions', await ev(() => [...document.querySelectorAll('.page [data-act], #tb-acts [data-act], #fab')].map(b => (b.textContent.trim() || b.getAttribute('aria-label') || '') + '|' + (b.dataset.act || b.id)).filter(x => /слов|dict|export|экспорт|логин/i.test(x))));
    const dict = page.locator('.page [data-act], #tb-acts [data-act]').filter({ hasText: /словар|Словар/ }).first();
    if (await dict.count()) await tap(dict, 'Login wordlist'); else { await tap('#tb-acts [data-act^="menu"], #tb-acts [aria-label="Ещё"], #tb-acts [aria-label="Меню"]', '⋮ menu'); await shot('docs_menu'); note('menu', await ev(() => [...document.querySelectorAll('.sheet.show [data-act]')].map(b => b.textContent.trim().slice(0, 40)))); const m = page.locator('.sheet.show [data-act]').filter({ hasText: /ловар|логин/ }).first(); if (await m.count()) await tap(m, 'wordlist item'); }
    await shot('dict_sheet');
    note('dict', await h.cur(), await ev(() => document.querySelector('.sheet.show')?.innerText.slice(0, 400)));
    const share = page.locator('.sheet.show [data-act]').filter({ hasText: /Поделиться|Сохранить|Экспорт/ }).last();
    await tap(share, 'Share/Export');
    await shot('dict_share');
    note('after-share', await h.cur(), await ev(() => document.querySelector('.sheet.show')?.innerText.slice(0, 300)));
    R.dict = h.reset();

    // 4. Report.
    await h.go('/p/overview'); h.reset();
    await nav('Отчёты');
    await shot('reports');
    await tap('#fab', 'FAB New report');
    await shot('report_new');
    note('rp-opts', await ev(() => [...document.querySelectorAll('.page [data-act]')].map(b => b.textContent.trim().slice(0, 25) + '|' + b.dataset.act).slice(0, 60)));
    const hi = page.locator('.page [data-act]').filter({ hasText: /^Высокий$|^Высокий\+?$/ }).first();
    if (await hi.count()) await tap(hi, 'High'); else note('no-high-chip');
    note('rp-state', await ev(() => JSON.stringify((FOCA.db.settings.report || {}).draft || {}).slice(0, 300)));
    await shot('report_high');
    const build = page.locator('.page [data-act], .foot [data-act]').filter({ hasText: /Сформировать/ }).first();
    await tap(build, 'Build');
    await wait(3500);
    await shot('report_built');
    note('built', await h.cur(), await ev(() => document.querySelector('.page')?.innerText.slice(0, 300)));
    const sh = page.locator('[data-act]').filter({ hasText: /Поделиться/ }).first();
    await tap(sh, 'Share');
    await shot('report_share');
    note('share', await ev(() => document.querySelector('.sheet.show')?.innerText.slice(0, 300)));
    const app = page.locator('.sheet.show [data-act]').filter({ hasText: /Signal/ }).first();
    if (await app.count()) await tap(app, 'Signal');
    R.report = h.reset();
  } catch (e) { note('ERR', e.message.split('\n')[0]); }
  console.log('s2', JSON.stringify({ R, log: h.log }, null, 0));
};
