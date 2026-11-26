// Settings-area screens in English and Ukrainian: settings hub, API keys, network, traffic, security, background
// work, appearance, about, signatures, lock screen, reports list and report builder.
// EN views must contain no Cyrillic (except demo data values), UK views no Russian-only letters (ы э ъ ё).
// Run: qa/shoot.sh --routes none --out $PWD/qa/out/i18n-settings --w 360 --steps $PWD/qa/scenarios/i18n-settings/steps.mjs
const arg = k => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : null; };
const W = arg('w') || 393;
// Demo data values that may legitimately stay Cyrillic in any language (project names, people, sample files,
// sample key states, underscore-joined report file names) plus the language endonyms of the language picker.
const DATA_RE = /(Контосо|Иванов[а-я]*|Петров[а-я]*|Сидоров[а-я]*|Смирнов[а-я]*|Кузнецов[а-я]*|Отчёт[^\s]*|Звіт[^\s]*|отчет[^\s]*|ключ отозван|баланс \$[\d,]+|Русский|Українська|[А-Яа-яЁёІіЇїЄє]+_[^\s]+)/g;
export default async (page, { out, go, prep }) => {
  const results = [];
  const ok = (name, cond, info = '') => { results.push(`${cond ? 'OK  ' : 'FAIL'} ${name}${info ? ' - ' + info : ''}`); };
  const text = () => page.evaluate(() => {
    // Data, not UI chrome: report names, the appearance preview rows (a real finding/document of the project) and
    // the core's template description, which is shown in the report language on purpose.
    const skip = [...document.querySelectorAll('.rp-hist .t, .rp-name, .mono, .st-preview .t, .st-preview .s, .rp-tpl-desc b, .rp-tpl-hint')].map(e => e.innerText).filter(Boolean);
    const roots = [document.querySelector('#app') || document.body];
    const parts = roots.map(r => skip.reduce((t, s) => t.split(s).join(''), r.innerText || ''));
    const attrs = [...document.querySelectorAll('[aria-label],[title],[placeholder]')]
      .filter(e => !e.closest('[hidden]'))
      .map(e => [e.getAttribute('aria-label'), e.getAttribute('title'), e.getAttribute('placeholder')].filter(Boolean).join(' '));
    return parts.concat(attrs).join('\n');
  });
  const setLang = async l => {
    await page.evaluate(l => FOCA.i18n.setLang(l), l);
    await page.waitForTimeout(250);
  };
  const click = async sel => { const b = await page.$(sel); if (b) { await b.click().catch(() => {}); await page.waitForTimeout(250); } return !!b; };
  const views = [
    ['settings', async () => { await go('/settings'); }],
    ['keys', async () => { await go('/settings/keys'); }],
    ['key-sheet', async () => { await go('/settings/keys'); await click('[data-act="st-key:shodan"]'); }],
    ['network', async () => { await go('/settings/network'); }],
    ['power', async () => { await go('/settings/power'); }],
    ['security', async () => { await go('/settings/security'); }],
    ['battery', async () => { await go('/settings/battery'); }],
    ['appearance', async () => { await go('/settings/appearance'); }],
    ['about', async () => { await go('/settings/about'); }],
    ['changelog', async () => { await go('/settings/about'); await page.evaluate(() => FOCA.actions['st-changes']()); await page.waitForTimeout(250); }],
    ['signatures', async () => { await go('/settings/signatures'); await page.waitForTimeout(300); }],
    ['lock', async () => { await go('/lock'); }],
    ['reports', async () => { await go('/p/reports'); }],
    ['report-new', async () => { await go('/p/report-new'); }],
  ];
  const only = (arg('only') || '').split(',').filter(Boolean);
  await go('/projects');
  for (const lang of ['en', 'uk']) {
    await setLang(lang);
    for (const [name, open] of views) {
      if (only.length && !only.includes(name)) continue;
      try {
        await open();
        await prep();
        await page.waitForTimeout(150);
        const t = (await text()).replace(DATA_RE, '');
        const bad = lang === 'en' ? t.match(/[^\n]{0,30}[А-Яа-яЁёІіЇїЄєҐґ][^\n]{0,30}/g) : t.match(/[^\n]{0,30}[ыэъёЫЭЪЁ][^\n]{0,30}/g);
        ok(`${lang} ${name}: no ${lang === 'en' ? 'Cyrillic' : 'Russian-only letters'}`, !bad, bad ? [...new Set(bad)].slice(0, 6).join(' | ') : '');
        const ov = await page.evaluate(() => { const pg = document.querySelector('.page'); return pg ? pg.scrollWidth - pg.clientWidth : 0; });
        ok(`${lang} ${name}: no horizontal overflow`, ov <= 1, `${ov}px`);
        await page.screenshot({ path: `${out}/i18n_${lang}_${name}_${W}.png` });
        await page.evaluate(() => FOCA.closeSheet && FOCA.closeSheet());
      } catch (e) {
        ok(`${lang} ${name}: opened`, false, String(e.message || e).slice(0, 200));
      }
    }
  }
  await setLang('auto');
  for (const r of results) console.log(r);
  const fails = results.filter(r => r.startsWith('FAIL')).length;
  console.log(`${results.length - fails} OK, ${fails} FAIL`);
};
