export default async (page) => {
  const r = await page.evaluate(() => ["example.com","*.example.com","https://a.example.com/x?y=1","ftp://x.com","8.8.8.8","8.8.8.256","10.0.0.0/24","10.0.0.0/8","10.0.0.1-10.0.0.50","10.0.0.1-20","10.0.0.9-10.0.0.1","AS15169","ASabc1","ТОВ «Ромашка»","Google LLC","Олена Коваленко","a@b.ua","a@b","contoso..ua","localhost","192.168.1","домен.укр","Microsoft"].map(x => x + " => " + JSON.stringify(FOCA.parseTarget(x))));
  console.error(r.join("\n"));
  // Long press on a card.
  await page.goto(new URL('../../../ui/index.html#/projects', import.meta.url).href); await page.waitForTimeout(300);
  const b = await page.locator('[data-pj="agro"]').boundingBox();
  await page.mouse.move(b.x + 150, b.y + 30); await page.mouse.down(); await page.waitForTimeout(700); await page.mouse.up(); await page.waitForTimeout(300);
  console.error("sheet:", await page.evaluate(() => document.querySelector('.sheet.show h3')?.textContent), "route:", await page.evaluate(() => FOCA.current()));
  await page.evaluate(() => FOCA.closeSheet()); await page.waitForTimeout(300);
  await page.locator('[data-pj="agro"] .pj-name').click(); await page.waitForTimeout(300);
  console.error("after tap route:", await page.evaluate(() => FOCA.current() + " " + FOCA.project.name));
  // Field on the projects screen → /new.
  await page.goto(new URL('../../../ui/index.html#/projects', import.meta.url).href); await page.waitForTimeout(300);
  await page.fill('#pj-q', 'acme.ua'); await page.keyboard.press('Enter'); await page.waitForTimeout(400);
  console.error("new:", await page.evaluate(() => FOCA.current() + " " + FOCA.state.launch.targets.map(t => t.v).join(",")));
  // Textarea input with a newline and a duplicate.
  await page.fill('#la-in', 'acme.ua\n1.2.3.4\nbad..ua\n'); await page.waitForTimeout(200);
  console.error("chips:", await page.evaluate(() => [...document.querySelectorAll('.la-chip-v')].map(e => e.textContent).join(" | ")));
};
