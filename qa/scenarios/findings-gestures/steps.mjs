// Findings gestures: swipes, long press, finding sheets.
export default async (page, { out, W, prep }) => {
  const shot = async n => { await page.waitForTimeout(350); await page.screenshot({ path: `${out}/step_${n}_${W}.png` }); };
  const log = [];
  const box = async i => {  await page.evaluate(i => document.querySelectorAll('.fd-card')[i].scrollIntoView({ block: 'center' }), i); await page.waitForTimeout(150); return page.locator('.fd-card').nth(i).boundingBox(); };
  const open = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };
  await open('/p/findings');
  // Swipe right: mid-gesture.
  let b = await box(0);
  const y = b.y + b.height / 2;
  await page.mouse.move(b.x + 40, y); await page.mouse.down();
  for (let i = 1; i <= 10; i++) await page.mouse.move(b.x + 40 + i * 16, y + 2);
  await shot('01_swipe_right_mid');
  await page.mouse.up(); await shot('02_after_confirm_snack');
  log.push({ after_confirm: await page.evaluate(() => FOCA.demoFindings.filter(f => f.status === 'confirmed').map(f => f.id)) });
  // Undo.
  await page.click('#snack .sn-a'); await page.waitForTimeout(300);
  log.push({ after_undo: await page.evaluate(() => FOCA.demoFindings.filter(f => f.status === 'confirmed').map(f => f.id)) });
  // Swipe left.
  b = await box(1);
  await page.mouse.move(b.x + b.width - 30, b.y + 30); await page.mouse.down();
  for (let i = 1; i <= 10; i++) await page.mouse.move(b.x + b.width - 30 - i * 15, b.y + 31);
  await shot('03_swipe_left_mid');
  await page.mouse.up(); await page.waitForTimeout(500);
  // A vertical gesture must not swipe.
  b = await box(0);
  await page.mouse.move(b.x + 100, b.y + 20); await page.mouse.down();
  for (let i = 1; i <= 8; i++) await page.mouse.move(b.x + 104, b.y + 20 + i * 12);
  log.push({ vertical_transform: await page.evaluate(() => document.querySelector('.fd-card').style.transform || 'none') });
  await page.mouse.up(); await page.waitForTimeout(300);
  log.push({ route_after_vertical: await page.evaluate(() => FOCA.current()) });
  // Long press → selection mode.
  b = await box(0);
  await page.mouse.move(b.x + 100, b.y + 30); await page.mouse.down(); await page.waitForTimeout(650); await page.mouse.up();
  await page.waitForTimeout(200);
  await page.locator('.fd-card').nth(2).click(); await page.locator('.fd-card').nth(3).click();
  await shot('04_select_mode');
  // System Back leaves selection mode.
  await page.goBack(); await page.waitForTimeout(400);
  log.push({ after_back: await page.evaluate(() => ({ sel: !!FOCA.state.findings.sel, route: FOCA.current(), body: document.body.className })) });
  // Select again → severity.
  b = await box(0);
  await page.mouse.move(b.x + 100, b.y + 30); await page.mouse.down(); await page.waitForTimeout(650); await page.mouse.up();
  await page.waitForTimeout(200);
  await page.click('[data-act="fd-bulk-sev"]'); await shot('05_bulk_sev_sheet');
  await page.goBack(); await page.waitForTimeout(400);
  log.push({ after_back_sheet: await page.evaluate(() => ({ sel: !!FOCA.state.findings.sel, sheet: !!document.querySelector('.sheet.show'), route: FOCA.current() })) });
  await page.goBack(); await page.waitForTimeout(400);
  log.push({ after_back2: await page.evaluate(() => ({ sel: !!FOCA.state.findings.sel, route: FOCA.current() })) });
  // Filters.
  await page.click('[data-act="fd-filters"]'); await page.waitForTimeout(300);
  await page.locator('.sheet .chip[data-v="crit"]').click(); await page.locator('.sheet .chip[data-v="web"]').click();
  await shot('06_filters_sheet');
  await page.click('#fd-apply'); await shot('07_filtered_list');
  // Card: status, note, photo.
  await open('/p/finding/4');
  // The secret in evidence is shown in full right away (as in Secrets).
  await page.evaluate(() => document.querySelector('.fd-ev').scrollIntoView({ block: 'center' }));
  await shot('08_detail_revealed');
  await page.click('.fd-status'); await shot('09_status_sheet');
  await page.click('[data-act="fd-status-set:4:confirmed"]'); await page.waitForTimeout(300);
  await page.click('[data-act="fd-note:4"]'); await page.waitForTimeout(300); await page.fill('#fd-nt', 'Проверено вручную: пароль действителен на SRV-SQL02 (по словам ИТ).');
  await shot('10_note_sheet');
  await page.click('#fd-nsave'); await page.waitForTimeout(300);
  await page.click('[data-act="fd-photo:4:cam"]'); await page.waitForTimeout(300);
  await page.evaluate(() => document.querySelector('.fd-photos').scrollIntoView({ block: 'center' }));
  await shot('11_detail_notes_photos');
  await page.click('.fd-pn .btn:last-child');
  await page.waitForTimeout(400);
  log.push({ next_route: await page.evaluate(() => FOCA.current()) });
  console.error(JSON.stringify(log));
};
