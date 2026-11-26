// Active phase with contract targets (demo targets) + flow 6 (keys/proxy from the wizard).
export default async (page, ctx) => { const log = []; try { await run(page, ctx, log); } catch (e) { log.push({ ERR: String(e).slice(0, 300) }); } finally { console.error('L2LOG ' + JSON.stringify(log)); } };
const run = async (page, { out, W, prep }, log) => {
  let taps = 0;
  const shot = async n => { await page.waitForTimeout(400); await page.screenshot({ path: `${out}/s1b_${n}.png` }); };
  const cur = () => page.evaluate(() => FOCA.current());
  const tap = async (sel, note) => { const l = page.locator(sel).first(); await l.scrollIntoViewIfNeeded({ timeout: 4000 }); const b = await l.boundingBox(); await l.click({ timeout: 4000 }); taps++; await page.waitForTimeout(350); log.push({ taps, note, y: b && Math.round(b.y + b.height / 2), h: b && Math.round(b.height), route: await cur() }); };
  const hold = async (sel, note) => { const l = page.locator(sel).first(); await l.scrollIntoViewIfNeeded(); const b = await l.boundingBox(); await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2); await page.mouse.down(); await page.waitForTimeout(1500); await page.mouse.up(); taps++; await page.waitForTimeout(500); log.push({ taps, note: 'HOLD ' + note, route: await cur() }); };
  const open = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };
  await open('/projects');
  await tap('[data-pj="contoso"] .pj-name', 'open contoso project');
  log.push({ fab: await page.locator('#fab.show').count(), mini: await page.evaluate(() => document.querySelector('#mini').classList.contains('show')), projCardScanning: true });
  await shot('00_overview_contoso');
  // Flow 6: keys and proxy from the wizard.
  await page.evaluate(() => FOCA.go('/new'));
  log.push({ targets: await page.evaluate(() => FOCA.state.launch.targets.map(t => t.v)), errors: await page.evaluate(() => FOCA.state.launch.errors.map(t => t.v)) });
  await shot('01_new_seeded');
  await page.click('#la-in'); await page.keyboard.type('draft-not-committed.ua');
  await tap('[data-act="la-adv"]', 'Advanced');
  await page.evaluate(() => { const p = FOCA.page(); p.scrollTop = p.querySelector('.la-src').offsetTop - 120; });
  await shot('02_adv_sources');
  await tap('.la-src [data-act="go:/settings"]', 'Specify (Censys key)');
  await shot('03_settings_from_wizard');
  await tap('[data-act="st-go:/settings/keys"]', 'API keys');
  await tap('[data-act="st-key:censys"]', 'Censys');
  await shot('04_key_sheet');
  await page.fill('#st-kv', 'censysID123:secretABCDEFG'); taps++;
  await tap('[data-act="st-keye"]', 'eye: show key');
  log.push({ keyVisibleWithoutBio: await page.evaluate(() => document.getElementById('st-kv').type) });
  await shot('05_key_revealed');
  await tap('[data-act="st-ksave:censys"]', 'Save');
  await page.goBack(); await page.waitForTimeout(350); await page.goBack(); await page.waitForTimeout(400);
  log.push({ backTo: await cur(), censysPill: await page.evaluate(() => [...document.querySelectorAll('.la-src')].map(r => r.textContent.replace(/\s+/g, ' ').trim()).filter(t => /Censys/.test(t))), adv: await page.evaluate(() => FOCA.state.launch.adv) });
  await page.evaluate(() => { const p = FOCA.page(); p.scrollTop = p.querySelector('#la-proxy').offsetTop - 200; });
  await shot('06_back_in_wizard_proxy');
  log.push({ proxyWizard: await page.evaluate(() => document.querySelector('#la-proxy').selectedOptions[0].textContent), proxySettings: await page.evaluate(() => FOCA.state.settings.net) });
  // Active phase with contract targets.
  await page.evaluate(() => { FOCA.page().scrollTop = 0; });
  await tap('[data-act="la-prof:full"]', 'Full profile');
  await tap('#la-start', 'Start scan: confirm');
  await tap('.la-agree', 'authorization present');
  await shot('07_confirm_ok');
  await hold('[data-hold="la-go-active"]', 'Hold to start');
  log.push({ after_active: await cur(), scan: await page.evaluate(() => ({ running: FOCA.scan.running, active: FOCA.scan.active, profile: FOCA.scan.profile, egress: FOCA.scan.egress })), activebar: await page.evaluate(() => document.querySelector('#activebar').classList.contains('show')) });
  await shot('08_after_active_start');
  await tap('#mini', 'mini-panel');
  await shot('09_scan_screen');
  log.push({ total_taps: taps });
};
