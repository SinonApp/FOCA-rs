// Dumps screen texts to re-check older items (read only).
import fs from 'fs';
export default async (page, { out }) => {
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const L = {};
  const R = ['/settings/power', '/settings/security', '/settings/network', '/settings/battery', '/p/doc/2', '/p/doc/5', '/p/doc/6', '/p/entity/software/0', '/p/entity/software/word2013', '/p/entity/printer/0', '/p/entity/host/mail.contoso.example', '/p/entity/pc/SRV-SQL02', '/p/entity/host/SRV-SQL02', '/p/graph/host/SRV-SQL02', '/p/entity/person/o.kovalenko', '/p/entity/email/o.kovalenko@contoso.example', '/p/finding/1', '/p/finding/23', '/p/entity/pc/MAIL01', '/p/graph/pc/MAIL01', '/p/data/os', '/p/scan-stopped/battery', '/p/scan-stopped/vpn', '/settings/plugin/sqli'];
  const q = await ev(() => FOCA.db.docs.find(d => d.status_code === 'queued').id);
  R.push('/p/doc/' + q);
  for (const r of R) { await ev(r => FOCA.go(r), r); await wait(320); L[r] = await ev(() => ((FOCA.page() || document.querySelector('.page'))?.innerText || '').replace(/\n+/g, ' / ')); }
  await ev(() => FOCA.api.project_open('logistics')); await wait(200);
  await ev(() => FOCA.go('/settings/plugin/sqli')); await wait(300);
  L['kyiv:/settings/plugin/sqli'] = await ev(() => FOCA.page().innerText.replace(/\n+/g, ' / '));
  fs.writeFileSync(out + '/static.json', JSON.stringify(L, null, 1));
};
