// System Back after opening a deep link.
export default async (page, { prep }) => {
  const out = [];
  for (const r of ['/p/scan', '/p/scan-stopped/vpn', '/new', '/p/finding/4', '/settings/keys', '/confirm-active', '/p/preflight', '/p/scope', '/p/overview']) {
    await page.waitForTimeout(300); await page.goto('about:blank').catch(()=>{}); await page.waitForTimeout(200); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(300); await prep(); await page.waitForTimeout(300);
    const b = await page.evaluate(() => ({ cur: FOCA.current(), hl: history.length, st: history.state }));
    let a;
    try { await page.evaluate(() => history.back()); await page.waitForTimeout(700); a = page.url().includes('index.html') ? await page.evaluate(() => ({ cur: FOCA.current() })) : 'LEFT APP -> ' + page.url(); } catch (e) { a = 'NAV-AWAY: ' + e.message.split('\n')[0]; }
    if (typeof a === 'object' && a === null) a = 'null';
    out.push({ r, before: b, after: a, url: page.url() });
  }
  console.log('DL', JSON.stringify({ log: out }));
};
