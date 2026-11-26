// Scan-area screens in English and Ukrainian: launch wizard, scan, sources, wordlists, tools, queue, scope.
// EN views must contain no Cyrillic (except demo data values), UK views no Russian-only letters (ы э ъ ё).
// Run: qa/shoot.sh --routes none --out $PWD/qa/out/i18n-scan --w 360 --steps $PWD/qa/scenarios/i18n-scan/steps.mjs
const arg = k => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : null; };
const W = arg('w') || 393;
// Demo data values that may legitimately stay Cyrillic in any language (project names, people, sample files).
const DATA_RE = /(Контосо|Иванов[а-я]*|Петров[а-я]*|Сидоров[а-я]*|Смирнов[а-я]*|Кузнецов[а-я]*|Отчёт[^\s]*|отчет[^\s]*)/g;
export default async (page, { out, go, prep }) => {
  const results = [];
  const ok = (name, cond, info = '') => { results.push(`${cond ? 'OK  ' : 'FAIL'} ${name}${info ? ' - ' + info : ''}`); };
  const text = () => page.evaluate(() => {
    // Data, not UI chrome: wordlist catalogue, scope card values, out-of-scope reasons from the core and
    // source error messages sent by the core.
    const skip = [...document.querySelectorAll('[data-wl] .t, [data-wl] .s, .kvr .v, .scn-owhy, .scn-ohint, .scn-oblk, .scn-osrc')]
      .map(e => e.innerText).filter(Boolean);
    for (const s of (window.FOCA && FOCA.scan && FOCA.scan.sources) || []) {
      if (!s.error) continue;
      const m = String(s.error).replace(/^капча \/ заблокировано:?\s*/i, '').trim();
      skip.push(s.error, m, m && m[0].toUpperCase() + m.slice(1));
    }
    skip.sort((a, b) => b.length - a.length);
    const roots = [document.querySelector('#app') || document.body];
    const parts = roots.map(r => skip.reduce((t, s) => t.split(s).join(''), r.innerText || ''));
    const attrs = [...document.querySelectorAll('[aria-label],[title],[placeholder]')]
      .filter(e => !e.closest('[hidden]'))
      .map(e => [e.getAttribute('aria-label'), e.getAttribute('title'), e.getAttribute('placeholder')].filter(Boolean).join(' '))
      .map(a => skip.reduce((t, s) => t.split(s).join(''), a));
    return parts.concat(attrs).join('\n');
  });
  const setLang = async l => {
    await page.evaluate(l => FOCA.i18n.setLang(l), l);
    await page.waitForTimeout(250);
  };
  const views = [
    ['new', async () => { await go('/new'); }],
    ['new-step2', async () => {
      await go('/new');
      await page.evaluate(() => { const i = document.querySelector('#nw-targets, textarea, input[type=text]'); if (i) { i.value = 'example.com'; i.dispatchEvent(new Event('input', { bubbles: true })); } });
      const nx = await page.$('[data-act="nw-next"]');
      if (nx) { await nx.click().catch(() => {}); await page.waitForTimeout(300); }
    }],
    ['scope', async () => { await go('/p/scope'); }],
    ['scan-idle', async () => { await go('/p/scan'); }],
    ['scan-run', async () => {
      await go('/p/scan');
      await page.evaluate(() => { FOCA.actions['scan-start']({ profile: 'std' }); FOCA.scanDemo.ff(20); FOCA.actions['scan-pause'] && FOCA.actions['scan-pause'](); });
      await page.waitForTimeout(600);
    }],
    ['scan-stopped', async () => { await go('/p/scan-stopped/error'); }],
    ['out-of-scope', async () => { await go('/p/out-of-scope'); }],
    ['sources', async () => {
      await go('/settings/sources');
      for (const g of ['search', 'sub', 'key']) { const b = await page.$(`[data-act="src-open:${g}"]`); if (b) { await b.click(); await page.waitForTimeout(120); } }
    }],
    ['wordlists', async () => { await go('/settings/wordlists'); await page.waitForTimeout(300); }],
    ['tools-file', async () => { await go('/tools'); }],
    ['tools-mail', async () => { await go('/tools'); await page.click('[data-act="tbx-tab:mail"]'); await page.waitForTimeout(150); }],
    ['tools-host', async () => { await go('/tools'); await page.click('[data-act="tbx-tab:host"]'); await page.waitForTimeout(150); }],
    ['tools-secret', async () => { await go('/tools'); await page.click('[data-act="tbx-tab:secret"]'); await page.waitForTimeout(150); }],
    ['tools-log', async () => { await go('/tools'); await page.click('[data-act="tbx-tab:log"]'); await page.waitForTimeout(150); }],
    ['queue', async () => { await go('/queue'); }],
  ];
  await go('/projects');
  for (const lang of ['en', 'uk']) {
    await setLang(lang);
    for (const [name, open] of views) {
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
