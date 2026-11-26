// Positive control for xss_sweep: the hook catches execution, while the payload is shown as TEXT.
export default async (page, o) => {
  await page.addInitScript(() => { window.__xs = []; window.__x = n => { window.__xs.push(n); }; });
  const api = async (cmd, args = {}) => { const r = await fetch(o.real + '/invoke', { method: 'POST', body: JSON.stringify({ cmd, args }) }); return (await r.json()).result; };
  await o.go('/projects');
  await api('project_open', { id: 'xss-passive' });
  const s = await api('project_snapshot', { id: 'xss-passive' });
  for (const d of s.docs) {
    await o.go('/p/doc/' + d.id); await page.waitForTimeout(500);
    const t = await page.evaluate(() => document.querySelector('.page').innerText);
    console.log('R1_CTRL doc', d.id, 'payload-as-text:', (t.match(/onerror=__x\(\d+\)/g) || []).join(' '));
  }
  await o.go('/p/data/people'); await page.waitForTimeout(500);
  console.log('R1_CTRL people text:', ((await page.evaluate(() => document.querySelector('.page').innerText)).match(/onerror=__x\(\d+\)/g) || []).join(' '));
  await page.evaluate(() => document.body.insertAdjacentHTML('beforeend', '<img src=x onerror=__x(999)>'));
  await page.waitForTimeout(500);
  console.log('R1_CTRL hook', JSON.stringify(await page.evaluate(() => window.__xs)));
  // Global search for the payload.
  await page.evaluate(() => window.FOCA && FOCA.actions && FOCA.actions['gsearch'] && FOCA.actions['gsearch']());
};
