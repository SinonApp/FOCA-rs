export default async (page, { out, W, prep }) => {
  await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#/p/map', import.meta.url).href); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300);
  const b = await page.locator('.v2m-pt').first().boundingBox(); await page.mouse.click(b.x + b.width / 2, b.y + b.height / 2);
  await page.waitForTimeout(400); await page.screenshot({ path: `${out}/tab_sheet_${W}.png` });
  await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#/p/graph/person/a.bondar', import.meta.url).href); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300);
  const g = await page.locator('.v2g-n.v2-t-pc:not(.ctr)').first().boundingBox(); await page.mouse.click(g.x + g.width / 2, g.y + g.height / 2);
  await page.waitForTimeout(700); await page.screenshot({ path: `${out}/tab_peek_${W}.png` });
};
