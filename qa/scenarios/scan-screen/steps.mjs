// Scan screen steps: start the demo scan, fast-forward time, take screenshots.
const arg = k => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : null; };
const sfx = () => `${arg('w') || 393}_fs${arg('fs') || 1}_${arg('theme') || 'dark'}`;
const only = (process.env.SCN_SHOTS || 'run,active,stop,sheet').split(',');
export default async (page, { out, prep }) => {
  const tall = async (name) => {
    const h = await page.evaluate(() => document.querySelector('.page').scrollHeight);
    const W = page.viewportSize().width; const H0 = page.viewportSize().height;
    await page.setViewportSize({ width: W, height: Math.min(4000, Math.max(H0, h + 200)) }); await page.waitForTimeout(250);
    await page.screenshot({ path: `${out}/${name}_${sfx()}.png` });
    await page.setViewportSize({ width: W, height: H0 });
  };
  const open = async (r) => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(200); await prep(); await page.waitForTimeout(200); };
  if (only.includes('run')) {
    await open('/p/scan');
    await page.evaluate(() => { FOCA.actions['scan-start']({ profile: 'std' }); FOCA.scanDemo.ff(+(window.__ff || 20)); });
    await page.waitForTimeout(1300);
    await page.screenshot({ path: `${out}/run_${sfx()}.png` });
    await tall('runtall');
    // Mini panel on the overview.
    await page.evaluate(() => FOCA.go('/p/overview')); await page.waitForTimeout(500);
    await page.screenshot({ path: `${out}/mini_${sfx()}.png` });
  }
  if (only.includes('active')) {
    await open('/p/scan');
    await page.evaluate(() => { FOCA.actions['scan-start']({ profile: 'full', active: true, active_ack: true }); FOCA.scanDemo.ff(22); FOCA.actions['scan-pause'](); });
    await page.waitForTimeout(800);
    await tall('active');
  }
  if (only.includes('sheet')) {
    await open('/p/scan');
    await page.evaluate(() => { FOCA.actions['scan-start']({ profile: 'passive' }); FOCA.scanDemo.ff(15); FOCA.actions['scan-stop'](); });
    await page.waitForTimeout(600);
    await page.screenshot({ path: `${out}/stopsheet_${sfx()}.png` });
  }
  if (only.includes('stop')) {
    // A real stop (kill switch) and the screen without a stopped scan.
    await open('/p/scan'); await page.evaluate(() => { FOCA.actions['scan-start']({ profile: 'full', active: true, active_ack: true }); FOCA.scanDemo.ff(15); FOCA.actions['scan-vpn-lost'](); }); await page.waitForTimeout(500); await tall('stopped_vpn');
    await open('/p/scan-stopped/error'); await tall('stopped_error');
  }
};
