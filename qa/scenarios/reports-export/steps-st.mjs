// Settings steps: key sheet, check, lock screen (wrong PIN, fingerprint).
export default async (page, { shot, go }) => {
  await go('/settings/keys');
  await page.click('[data-act="st-key:vt"]'); await shot('st_key_vt');
  await page.click('[data-act="st-kcheck:vt"]'); await page.waitForTimeout(1500); await shot('st_key_checked');
  await page.evaluate(() => FOCA.closeSheet());
  await go('/settings/network');
  await page.click('[data-act="st-pcheck"]'); await page.waitForTimeout(1600); await shot('st_net_proxy');
  await go('/lock'); await shot('st_lock');
  for (const d of ['1', '1', '1', '1']) await page.click(`[data-act="st-lk:${d}"]`);
  await page.waitForTimeout(200); await shot('st_lock_wrong');
  await page.click('[data-act="st-lk-bio"]'); await page.waitForTimeout(400); await shot('st_lock_bio');
  await page.waitForTimeout(1400);
  console.error('after bio route', await page.evaluate(() => FOCA.current() + ' lock:' + !!document.querySelector('.st-lock')));
  await go('/settings/security');
  await page.click('[data-act="go:/lock"]'); await page.waitForTimeout(300);
  for (const d of ['1', '2', '3', '4']) await page.click(`[data-act="st-lk:${d}"]`);
  await page.waitForTimeout(1000);
  console.error('after pin route', await page.evaluate(() => FOCA.current() + ' lock:' + !!document.querySelector('.st-lock')));
};
