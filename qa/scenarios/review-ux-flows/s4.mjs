// Report of confirmed high findings only + share. s5: scan + leave/return + offline/VPN. s7: global search.
export default async (page, ctx) => { const log = []; try { await run(page, ctx, log); } catch (e) { log.push({ ERR: String(e).slice(0, 400) }); } finally { console.error('L2LOG ' + JSON.stringify(log)); } };
const run = async (page, { out, W, prep }, log) => {
  let taps = 0;
  const shot = async n => { await page.waitForTimeout(400); await page.screenshot({ path: `${out}/s4_${n}.png` }); };
  const cur = () => page.evaluate(() => FOCA.current());
  const tap = async (sel, note) => { const l = page.locator(sel).first(); await l.scrollIntoViewIfNeeded({ timeout: 4000 }); const b = await l.boundingBox(); await l.click({ timeout: 4000 }); taps++; await page.waitForTimeout(380); log.push({ taps, note, y: b && Math.round(b.y + b.height / 2), h: b && Math.round(b.height), route: await cur() }); };
  const back = async note => { await page.goBack(); taps++; await page.waitForTimeout(400); log.push({ taps, note: 'BACK ' + (note || ''), route: await cur() }); };
  const open = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };
  // ---- s4 ----
  await open('/p/overview');
  await tap('#nav [data-tab="/p/reports"]', 'Reports tab');
  await shot('01_reports');
  await tap('#fab', 'FAB New report');
  log.push({ confirmedDefault: await page.evaluate(() => FOCA.state.reports.d.confirmed), minSev: await page.evaluate(() => FOCA.state.reports.d.minSev), foot: await page.evaluate(() => document.querySelector('.rp-foot-s').textContent) });
  await tap('[data-act="rp-d:minSev:high"]', 'Severity: High+');
  log.push({ foot2: await page.evaluate(() => document.querySelector('.rp-foot-s').textContent), included: await page.evaluate(() => { const d = FOCA.state.reports.d; return FOCA.demoFindings.filter(f => f.status === 'confirmed' && ['high', 'crit'].includes(f.sev)).map(f => f.sev + ':' + f.id); }) });
  await shot('02_constructor');
  // Switching the template: are the settings kept?
  await tap('[data-act="rp-d:tpl:brief"]', 'Summary template');
  log.push({ afterTplSwitch: await page.evaluate(() => ({ minSev: FOCA.state.reports.d.minSev, confirmed: FOCA.state.reports.d.confirmed })) });
  await tap('[data-act="rp-d:tpl:full"]', 'Full template again');
  await tap('[data-act="rp-d:minSev:high"]', 'High+ again');
  // Go back and return.
  await back('from the builder');
  await tap('#fab', 'FAB again');
  log.push({ afterReenter: await page.evaluate(() => FOCA.state.reports.d.minSev) });
  await tap('[data-act="rp-d:minSev:high"]', 'High+ (third time)');
  await tap('[data-act="rp-build"]', 'Build');
  await page.waitForTimeout(3300);
  await shot('03_built');
  await tap('[data-act="rp-b-share"]', 'Share…');
  await page.waitForTimeout(300);
  await shot('04_share');
  await tap('[data-act="rp-share-to:Signal"]', 'Signal');
  log.push({ s4_taps: taps, hist0: await page.evaluate(() => FOCA.state.reports.history[0].name) });
  // Does the preview of an old report show the current draft?
  await back('from the builder after sending');
  await page.evaluate(() => { FOCA.state.reports.d.lang = 'EN'; });
  await tap('.rp-hrow >> nth=1', 'old report from history (v2 UA)');
  log.push({ previewOfOldUsesDraftLang: await page.evaluate(() => document.querySelector('.rp-pinfo').textContent), sub: await page.evaluate(() => document.querySelector('#tb-s').textContent) });
  await shot('05_old_preview');
  // ---- s5 ----
  taps = 0;
  await open('/p/scan');
  log.push({ deepLinkScanBackDeadEnd: await page.evaluate(() => ({ backBtn: !document.querySelector('#tb-back').hidden, nav: document.querySelector('#nav').classList.contains('show') })) });
  await page.locator('#tb-back').click(); await page.waitForTimeout(300); log.push({ afterBackOnRootScan: await cur() });
  await open('/p/overview');
  await tap('[data-act="go:/p/scan"].btn', 'Details (scan)');
  await tap('[data-act="scan-demo:passive"]', 'Start demo scan');
  await page.evaluate(() => FOCA.scanDemo.ff(20));
  await tap('#tb-back', 'leave (back)');
  log.push({ routeAfterLeave: await cur(), nav: await page.evaluate(() => document.querySelector('#nav').classList.contains('show')) });
  await tap('#nav [data-tab="/p/data"]', 'Data tab');
  log.push({ miniOnData: await page.evaluate(() => ({ show: document.querySelector('#mini').classList.contains('show'), t: document.querySelector('#mi-t').textContent, s: document.querySelector('#mi-s').textContent })) });
  await shot('10_mini_on_data');
  await tap('[data-act="dt-seg:people"]', 'People');
  await tap('.list .row.tap >> nth=0', 'person');
  log.push({ miniOnEntity: await page.evaluate(() => document.querySelector('#mini').classList.contains('show')) });
  const mini = await page.locator('#mini').boundingBox(); const ppb = await page.locator('#mi-pp').boundingBox();
  log.push({ miniBox: mini && [Math.round(mini.y), Math.round(mini.height)], miniPauseBtn: ppb && [Math.round(ppb.width), Math.round(ppb.height)], miniPauseAria: await page.evaluate(() => document.querySelector('#mi-pp').getAttribute('aria-label')) });
  await tap('#mi-pp', 'pause in mini-panel');
  log.push({ pausedFeedback: await page.evaluate(() => ({ paused: FOCA.scan.paused, snack: document.querySelector('#snack').classList.contains('show') ? document.querySelector('#snack').textContent : '' })) });
  await tap('#mini .mi-txt', 'mini-panel → scan screen');
  log.push({ backStackDepthHint: await cur() });
  await back('from the scan screen');
  // Offline.
  await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  await page.evaluate(() => FOCA.setOffline(true));
  await page.waitForTimeout(300);
  log.push({ offline: await page.evaluate(() => ({ banner: document.querySelector('#offline').classList.contains('show'), running: FOCA.scan.running, paused: FOCA.scan.paused, mini: document.querySelector('#mi-t').textContent })) });
  await shot('11_offline');
  await open('/p/scan-stopped/vpn');
  await shot('12_vpn');
  log.push({ s5_taps: taps });
  // ---- s7 ----
  taps = 0;
  await open('/p/findings');
  const sp = await page.locator('#searchpill').boundingBox(); log.push({ searchPillY: sp && Math.round(sp.y), label: await page.evaluate(() => document.querySelector('#searchpill span').textContent) });
  await tap('#searchpill', '"Поиск по находкам" field');
  log.push({ route: await cur(), title: await page.evaluate(() => document.querySelector('#tb-t').textContent) });
  for (const q of ['TLS', 'AWS', 'bondar', 'info@']) {
    await page.fill('#gq', q); await page.waitForTimeout(250);
    log.push({ q, sections: await page.evaluate(() => [...document.querySelectorAll('#gres .sec-h h2')].map(h => h.textContent + ':' + h.parentElement.nextElementSibling.querySelectorAll('.row').length)), empty: await page.evaluate(() => !!document.querySelector('#gres .empty')) });
  }
  await page.fill('#gq', 'bondar'); await page.waitForTimeout(200);
  await tap('[data-act="gchip:Документы"]', 'Documents chip');
  log.push({ afterChip: await page.evaluate(() => [...document.querySelectorAll('#gres .sec-h h2')].map(h => h.textContent)) });
  await shot('20_search_chip');
  await tap('#gres .row.tap >> nth=0', 'first result');
  await back('back to search');
  log.push({ queryKept: await page.evaluate(() => document.querySelector('#gq') && document.querySelector('#gq').value) });
  await shot('21_search_after_back');
};
