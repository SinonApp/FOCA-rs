// Analysis-area screens in English and Ukrainian: findings (list, filters, card), infrastructure segments
// (certificates, mail policies, SaaS), analytics (graph, network map, timeline), document forensics blocks,
// text search, offline import and search rules.
// EN views must contain no Cyrillic, UK views no Russian-only letters (ы э ъ ё). Values that come from the
// demo data (finding titles and descriptions, document names and contents, tags, people) are excluded:
// only the screen chrome is checked on data-heavy views.
// Run: qa/shoot.sh --routes none --out $PWD/qa/out/i18n-analysis --w 360 --steps $PWD/qa/scenarios/i18n-analysis/steps.mjs
const arg = k => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : null; };
const W = arg('w') || 393;
// Demo data values that may legitimately stay Cyrillic in any language.
// Quoted names («…», “…») are preset/project/document names from the data.
const DATA_RE = /(Контосо|Приклад|Эталонный кейс|НД ТЗІ|КСЗІ|РНОКПП|ЄДРПОУ|договір[^\n<]*|"потужність приєднання"|звіт -2019|енерг\*|«[^»\n]*»|“[^”\n]*”)/g;
// Elements whose text is data (core/demo values), never UI chrome.
const SKIP = [
  '.fd-title', '.fd-desc', '.fd-ev', '.fd-tag', '.fd-tags', '.fd-notes', '.fd-note', '.fd-url', '.fd-hash', '.fd-src', '.fd-srcdoc',
  '.fd-card .t', '.fd-card .s', '.fd-card h3', '.fd-rec', '.fd-prov .v', '.fd-kv .v', '.fd-cat-v',
  '.mono', '.fx-quote', '.fx-diff', '.fx-sub', '.fx-break', '.fx-kv .v', '.fx-tli b', '.fx-gh', '.fx-files', '.fx-sample',
  '.ins-svg', '.ins-chain-l', '.ins-nm-r .t', '.ins-org-h b', '.chip', '.ins-ln-c', '.ins-src-v',
  '.row .t', '.row .s', '.lead', 'select option', '.tb-title', '#tb-sub', '.rel .t', '.dt-tags .pill.mute',
  'input', 'textarea',
];
export default async (page, { out, go, prep }) => {
  const results = [];
  const ok = (name, cond, info = '') => { results.push(`${cond ? 'OK  ' : 'FAIL'} ${name}${info ? ' - ' + info : ''}`); };
  const text = full => page.evaluate(([skip, full]) => {
    const root = document.querySelector('#app') || document.body;
    const clone = root.cloneNode(true);
    if (!full) clone.querySelectorAll(skip.join(',')).forEach(e => e.remove());
    // innerText needs layout: measure the clone off-screen.
    clone.style.cssText = 'position:absolute;left:-99999px;top:0;width:400px';
    document.body.appendChild(clone);
    const t = clone.innerText || '';
    const attrs = [...clone.querySelectorAll('[aria-label],[title],[placeholder]')]
      .map(e => [e.getAttribute('aria-label'), e.getAttribute('title'), e.getAttribute('placeholder')].filter(Boolean).join(' '));
    clone.remove();
    const sheet = document.querySelector('.sheet.open, .sheet[open], .sheet-wrap.open, .sheet');
    const st = sheet && sheet.offsetParent !== null ? sheet.innerText : '';
    return [t, st, ...attrs].join('\n');
  }, [SKIP, !!full]);
  const setLang = async l => {
    await page.evaluate(l => FOCA.i18n.setLang(l), l);
    await page.waitForTimeout(250);
  };
  const ev = (fn, a) => page.evaluate(fn, a);
  const closeSheet = () => ev(() => { const b = document.querySelector('[data-act="sheet-close"]'); if (b) b.click(); });
  const findingId = rule => ev(r => (FOCA.db.findings.find(x => x.provenance && x.provenance.rule === r) || FOCA.db.findings[0] || {}).id, rule);
  const docId = name => ev(n => (FOCA.db.docs.find(d => d.name === n) || {}).id, name);
  const openAll = () => ev(() => document.querySelectorAll('.fx-sec').forEach(d => { d.open = true; }));
  // Chrome of the findings list / finding card: titles, descriptions, hosts and tags are data.
  const LIST = '.seg, .fd-sums, .fd-top .pill, .fd-meta, .fd-hint, .fd-filters, .fd-chips, .empty, .fd-ctx';
  const CARD = '.sec-h, .kvr .k, .fd-cat, .fd-hero-top .pill, .fd-status, .fd-foot, .fd-code, .fd-std-h, .btn, .sec-a, .fd-none, .fd-scope, .fd-navrow';
  const SEG = '.dt-bar, .sec-h, .kvr .k, .pill, .fhint, .banner, .empty, .note';
  const views = [
    ['findings', async () => { await go('/p/findings'); }, false, LIST],
    // Source chips list the finding sources (data); the other chip groups are UI labels.
    ['findings-filters', async () => { await go('/p/findings'); await ev(() => FOCA.actions['fd-filters'] && FOCA.actions['fd-filters']()); await page.waitForTimeout(250); }, true, '.flabel, [data-g="sev"], [data-g="status"], [data-g="cat"], .fd-sortseg, .fd-evrow, #fd-host option[value=""], .sheet .btn'],
    ['finding-infra', async () => { await go(`/p/finding/${await findingId('infra.host_role_exposed')}`); }, false, CARD],
    ['finding-forensic', async () => { await go(`/p/finding/${await findingId('doc.bad_redaction')}`); }, false, CARD],
    // Segment bodies only: the data screen chrome (search, segment tabs) belongs to another screen file.
    ['certs', async () => { await go('/p/data/certs'); }, false, SEG],
    ['mailpol', async () => { await go('/p/data/mailpol'); }, false, SEG],
    ['saas', async () => { await go('/p/data/saas'); }, false, SEG],
    ['graph', async () => { await go('/p/graph'); await page.waitForTimeout(300); }],
    ['netmap', async () => { await go('/p/netmap'); await page.waitForTimeout(300); }],
    // Year lanes and the heat map; the rest of the timeline screen is another screen file.
    ['timeline', async () => { await go('/p/timeline'); await page.waitForTimeout(300); }, false, '.ins-lanes, .ins-heat'],
    ['doc-pdf', async () => { await go('/p/doc/1'); await openAll(); }, false, '.fx-secs'],
    ['doc-xlsx', async () => { await go(`/p/doc/${await docId('Перелік_обладнання_ТЕС-2.xlsx')}`); await openAll(); }, false, '.fx-secs'],
    ['doc-eml', async () => { await go(`/p/doc/${await docId('Re_Тендер_ТЕС-2_уточнення.eml')}`); await openAll(); }, false, '.fx-secs'],
    ['docs-search', async () => { await go('/p/docs-search'); }],
    ['import', async () => { await go('/import'); }],
    ['rules', async () => { await go('/p/rules'); await page.waitForTimeout(300); }],
  ];
  await go('/projects');
  for (const lang of ['en', 'uk']) {
    await setLang(lang);
    for (const [name, open, sheet, scope] of views) {
      try {
        await open();
        await prep();
        await page.waitForTimeout(200);
        let t;
        if (scope) {
          t = await ev(([sel, skip]) => {
            if (!document.querySelector(sel)) return '';
            // Section titles and field labels of the forensic blocks (values are document data).
            // Forensic blocks: section titles and notes only (field labels and pills carry document data).
            const sel2 = sel === '.fx-secs' ? '.fx-st, .fhint span, .fx-note' : '*';
            return [...document.querySelectorAll(sel)].flatMap(root => [...(sel2 === '*' ? [root] : []), ...root.querySelectorAll(sel2 === '*' ? '[aria-label],[title],[placeholder]' : sel2)])
              .filter(e => !e.closest(skip.join(',')))
              .map(e => [sel2 === '*' && e.matches(sel) ? e.innerText : sel2 !== '*' ? e.innerText : '', e.getAttribute('aria-label'), e.getAttribute('title'), e.getAttribute('placeholder')].filter(Boolean).join(' '))
              .join('\n');
          }, [scope, ['.fx-quote', '.fx-diff', '.mono', '.fx-break', '.fd-t', '.fd-h1', '.fd-tag', '.chip', '.fd-host']]);
        } else t = await text();
        t = t.replace(DATA_RE, '');
        const bad = lang === 'en' ? t.match(/[^\n]{0,30}[А-Яа-яЁёІіЇїЄєҐґ][^\n]{0,30}/g) : t.match(/[^\n]{0,30}[ыэъёЫЭЪЁ][^\n]{0,30}/g);
        ok(`${lang} ${name}: no ${lang === 'en' ? 'Cyrillic' : 'Russian-only letters'}`, !bad, bad ? [...new Set(bad)].slice(0, 6).join(' | ') : '');
        const ov = await page.evaluate(() => { const pg = document.querySelector('.page'); return pg ? pg.scrollWidth - pg.clientWidth : 0; });
        ok(`${lang} ${name}: no horizontal overflow`, ov <= 1, `${ov}px`);
        await page.screenshot({ path: `${out}/i18n_${lang}_${name}_${W}.png` });
        if (sheet) await closeSheet();
      } catch (e) {
        ok(`${lang} ${name}: opened`, false, String(e.message || e).slice(0, 200));
      }
    }
  }
  // Switching back to Russian restores the Russian chrome (the fallbacks are the original strings).
  await setLang('ru');
  await go('/p/findings');
  ok('ru findings: Russian chrome is back', /Находки|Новые|Сбросить/.test(await text(true)));
  await setLang('auto');
  for (const r of results) console.log(r);
  const fails = results.filter(r => r.startsWith('FAIL')).length;
  console.log(`${results.length - fails} OK, ${fails} FAIL`);
};
