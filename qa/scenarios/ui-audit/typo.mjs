// Typography audit of the rendered text on every route.
import fs from 'fs';
export default async (page, { out }) => {
  const routes = fs.readFileSync(new URL('../../routes.txt', import.meta.url), 'utf8').trim().split(',');
  const res = {};
  for (const r of routes) {
    await page.evaluate(r => { FOCA.reset(['/p/overview', r], 'none'); }, r);
    await page.waitForTimeout(100);
    const hits = await page.evaluate(() => {
      const out = [];
      const w = document.createTreeWalker(document.getElementById('app'), NodeFilter.SHOW_TEXT);
      const rx = [
        [/\S - \S/, 'hyphen instead of dash'], [/"/, 'straight quotes'], [/\.\.\./, 'three dots'],
        [/\d (КБ|МБ|ГБ|Б|с|мин|ч|%|м|км|стр\.?|дн\.?)(?![а-яё])/, 'plain space before unit'],
        [/\b(e-mail|Email|email)\b/, 'e-mail'],
        [/\b[A-Za-z]{4,}\b/, 'Latin script'],
      ];
      let n;
      while ((n = w.nextNode())) {
        const t = n.nodeValue; if (!t.trim()) continue;
        const el = n.parentElement; if (!el || el.closest('.mono, code, pre, .secret, svg, .rp-paper, input, textarea')) continue;
        const b = el.getBoundingClientRect(); if (!b.width) continue;
        for (const [re, k] of rx) if (re.test(t)) out.push(k + ': ' + t.trim().slice(0, 80));
      }
      return [...new Set(out)];
    });
    if (hits.length) res[r] = hits;
  }
  fs.writeFileSync(out + '/typo.json', JSON.stringify(res, null, 1));
};
