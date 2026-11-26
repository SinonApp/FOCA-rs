// Tools-area screens in English and Ukrainian: documents list and card (sheets included), hygiene before/after
// and the shared-file check, terms and permissions, Settings → Debug (all segments).
// EN views must contain no Cyrillic (except demo data values), UK views no Russian-only letters (ы э ъ ё).
// Run: qa/shoot.sh --routes none --out $PWD/qa/out/i18n-tools --w 360 --steps $PWD/qa/scenarios/i18n-tools/steps.mjs
const arg = k => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : null; };
const W = arg('w') || 393;
// Demo data values that may legitimately stay Cyrillic in any language (project names, people, sample files).
const DATA_RE = /(Контосо|Иванов[а-я]*|Петров[а-я]*|Сидоров[а-я]*|Смирнов[а-я]*|Кузнецов[а-я]*|Отчёт[^\s]*|отчет[^\s]*|Договір_оренди_2026\.pdf|\\\\[^\s|]+|стр\. \d+, Приложение \d+|в исключениях скоупа|Поддержка закончилась[\s\S]*?опубликованные позже\.|KEV не указывает[\s\S]*?производителя\.)/g;
// Elements that render data (file names, metadata values, log lines, URLs), not UI chrome.
const DATA_SEL = '.dt-fname, .dt-dh-name, .hy-fn, .kvr .v, .mono, .dt-rev-t, .dt-rev-w, .dbg-m, .dbg-tg, .dt-sec-where, .dt-url, [data-g] .chip, .dt-fchip span, .dt-doc .s, .dt-sec-type, .ctxbar-n, .dbg-ct, .avatar, [data-act^="go:/p/finding/"], [data-act^="dt-nav:/p/doc/"] .t';
export default async (page, { out, go, prep }) => {
  const results = [];
  const ok = (name, cond, info = '') => { results.push(`${cond ? 'OK  ' : 'FAIL'} ${name}${info ? ' - ' + info : ''}`); };
  const ev = (fn, a) => page.evaluate(fn, a);
  const wait = ms => page.waitForTimeout(ms);
  const text = () => page.evaluate(sel => {
    const skip = [...document.querySelectorAll(sel)].map(e => e.innerText).filter(Boolean).sort((a, b) => b.length - a.length);
    const roots = [document.querySelector('#app') || document.body, ...document.querySelectorAll('.sheet')];
    const strip = s => skip.reduce((t, x) => t.split(x).join(''), s || '');
    const parts = roots.map(r => strip(r.innerText));
    const attrs = [...document.querySelectorAll('[aria-label],[title],[placeholder]')]
      .filter(e => !e.closest('[hidden]') && !e.closest(sel))
      .map(e => [e.getAttribute('aria-label'), e.getAttribute('title'), e.getAttribute('placeholder')].filter(Boolean).join(' '))
      .map(strip);
    return parts.concat(attrs).join('\n');
  }, DATA_SEL);
  const setLang = async l => {
    await ev(l => FOCA.i18n.setLang(l), l);
    await wait(250);
  };
  const closeSheet = () => ev(() => FOCA.closeSheet && FOCA.closeSheet());
  const act = async (a, arg) => { await ev(([a, arg]) => FOCA.actions[a](arg), [a, arg]); await wait(250); };
  const firstDoc = () => ev(() => (FOCA.db.docs.find(d => d.status_code === 'analyzed') || FOCA.db.docs[0]).id);
  const photo = () => ev(() => FOCA.db.docs.find(d => d.ext === 'jpg' && d.gps && !FOCA.db.secrets.some(s => s.doc === d.id)).id);
  const views = [
    ['terms', async () => { await go('/terms'); }],
    ['permissions', async () => { await go('/permissions'); await wait(300); }],
    ['settings-terms', async () => { await go('/settings/terms'); await wait(300); }],
    ['docs-list', async () => { await go('/projects'); await go('/p/data/docs'); }],
    ['docs-select', async () => { await go('/p/data/docs'); await act('dd-sel-start'); }],
    ['docs-sort', async () => { await go('/p/data/docs'); await ev(() => FOCA.dataDocs.sortSheet()); await wait(250); }],
    ['docs-filters', async () => { await go('/p/data/docs'); await act('dd-filters'); }],
    ['doc-card', async () => { const id = await firstDoc(); await go('/p/doc/' + id); }],
    ['doc-photo', async () => { const id = await photo(); await go('/p/doc/' + id); }],
    ['doc-clean-sheet', async () => { const id = await firstDoc(); await go('/p/doc/' + id); await act('dd-clean', String(id)); }],
    ['doc-share-sheet', async () => { const id = await firstDoc(); await go('/p/doc/' + id); await act('dd-share', String(id)); }],
    ['doc-more-sheet', async () => { const id = await firstDoc(); await go('/p/doc/' + id); await act('dd-more', String(id)); }],
    ['clean-result', async () => {
      const id = await photo();
      await ev(id => { FOCA.state.v2.pf = { step: 1, files: [id], cleaned: [] }; FOCA.go('/p/preflight'); }, id); await wait(500);
      await act('v2pf-clean', String(id)); await wait(500);
      await act('hy-all');
    }],
    ['clean-result-dirty', async () => {
      await ev(() => { FOCA.state.v2.pf = { step: 1, files: [1], cleaned: [] }; FOCA.go('/p/preflight'); }); await wait(400);
      await act('v2pf-clean', '1'); await wait(500);
      await act('hy-share', '0');
    }],
    ['shared', async () => {
      await ev(() => FOCA_DEMO_BACKEND.invokeSync('demo_share', {})); await ev(() => FOCA.emit('shared', {})); await wait(700);
    }],
    ['debug-log', async () => { await go('/settings/debug/log'); await wait(300); }],
    ['debug-req', async () => { await go('/settings/debug/req'); await wait(300); }],
    ['debug-crash', async () => { await go('/settings/debug/crash'); await wait(300); }],
    ['debug-dev', async () => { await go('/settings/debug/dev'); await wait(300); }],
    ['debug-search', async () => { await go('/settings/debug/search'); await wait(300); await act('dbg-fp'); await wait(300); }],
    ['debug-clear-sheet', async () => { await go('/settings/debug/log'); await act('dbg-clear'); }],
  ];
  await go('/projects');
  for (const lang of ['en', 'uk']) {
    await setLang(lang);
    for (const [name, open] of views) {
      try {
        await closeSheet();
        await open();
        await prep();
        await wait(150);
        const t = (await text()).replace(DATA_RE, '');
        const bad = lang === 'en' ? t.match(/[^\n]{0,30}[А-Яа-яЁёІіЇїЄєҐґ][^\n]{0,30}/g) : t.match(/[^\n]{0,30}[ыэъёЫЭЪЁ][^\n]{0,30}/g);
        ok(`${lang} ${name}: no ${lang === 'en' ? 'Cyrillic' : 'Russian-only letters'}`, !bad, bad ? [...new Set(bad)].slice(0, 6).join(' | ') : '');
        const ov = await ev(() => { const pg = document.querySelector('.page'); return pg ? pg.scrollWidth - pg.clientWidth : 0; });
        ok(`${lang} ${name}: no horizontal overflow`, ov <= 1, `${ov}px`);
        await page.screenshot({ path: `${out}/i18n_${lang}_${name}_${W}.png` });
      } catch (e) {
        ok(`${lang} ${name}: opened`, false, String(e.message || e).slice(0, 200));
      }
      await ev(() => { if (FOCA.dataDocs && FOCA.dataDocs.selecting()) FOCA.dataDocs.exitSel(true); });
    }
  }
  await closeSheet();
  await setLang('auto');
  for (const r of results) console.log(r);
  const fails = results.filter(r => r.startsWith('FAIL')).length;
  console.log(`${results.length - fails} OK, ${fails} FAIL`);
};
