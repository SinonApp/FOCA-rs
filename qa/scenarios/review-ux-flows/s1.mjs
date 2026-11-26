// Flow 1: first run → new project → targets → scope → passive scan → active phase. Real clicks.
export default async (page, ctx) => { const log = []; try { await run(page, ctx, log); } catch (e) { log.push({ ERR: String(e).slice(0, 300) }); } finally { console.error('L2LOG ' + JSON.stringify(log)); } };
const run = async (page, { out, W, prep }, log) => {
  let taps = 0;
  const shot = async n => { await page.waitForTimeout(400); await page.screenshot({ path: `${out}/s1_${n}.png` }); };
  const cur = () => page.evaluate(() => FOCA.current());
  const tap = async (sel, note) => { const l = page.locator(sel).first(); await l.scrollIntoViewIfNeeded(); const b = await l.boundingBox(); await l.click(); taps++; await page.waitForTimeout(350); log.push({ taps, note, sel, y: b && Math.round(b.y + b.height / 2), h: b && Math.round(b.height), w: b && Math.round(b.width), route: await cur() }); };
  const hold = async (sel, note) => { const l = page.locator(sel).first(); await l.scrollIntoViewIfNeeded(); const b = await l.boundingBox(); await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2); await page.mouse.down(); await page.waitForTimeout(1500); await page.mouse.up(); taps++; await page.waitForTimeout(500); log.push({ taps, note: 'HOLD ' + note, y: Math.round(b.y + b.height / 2), route: await cur() }); };
  // First run.
  await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html', import.meta.url).href);
  await page.evaluate(() => localStorage.clear()); await page.reload(); await page.waitForTimeout(300); await prep(); await page.waitForTimeout(300);
  log.push({ start: await cur() });
  await shot('01_welcome1');
  await tap('.v2w-next', 'Next'); await tap('.v2w-next', 'Next');
  await shot('02_welcome3');
  await tap('.v2w-cons .checkrow', 'consent');
  await tap('[data-act="v2w-done"]', 'Later');
  await shot('03_projects');
  // New project through the new target field.
  await page.fill('#pj-q', 'newcorp.ua'); taps++; log.push({ taps, note: 'target input (focus+text)' });
  await tap('.pj-go', 'go');
  await shot('04_new');
  log.push({ newTargets: await page.evaluate(() => FOCA.state.launch.targets.map(t => t.v)), project: await page.evaluate(() => FOCA.project.name) });
  // Subnet.
  await page.click('#la-in'); await page.keyboard.type('10.20.30.0/24'); taps++;
  await tap('[data-act="la-commit"]', '+ add');
  // Exclusion: only under the advanced section.
  await tap('[data-act="la-adv"]', 'Advanced');
  await page.fill('#la-excl', '10.20.30.5'); taps++;
  await tap('[data-act="la-excl-add"]', 'add exclusion');
  log.push({ excl_launch: await page.evaluate(() => FOCA.state.launch.excl), excl_scope: await page.evaluate(() => FOCA.state.scope.excl) });
  await shot('05_new_adv');
  // Scope from the wizard.
  await page.evaluate(() => { FOCA.page().scrollTop = 0; });
  await tap('.sec-h [data-act="go:/p/scope"]', 'Scope');
  log.push({ scope_targets: await page.evaluate(() => FOCA.state.scope.targets.map(t => t.v)), scope_title_sub: await page.evaluate(() => document.querySelector('#tb-s').textContent) });
  await shot('06_scope');
  await tap('.la-addt', 'Add target (in scope)');
  log.push({ after_add_from_scope: await cur() });
  await page.goBack(); await page.waitForTimeout(400); log.push({ back1: await cur() });
  await page.goBack(); await page.waitForTimeout(400); log.push({ back2: await cur(), targetsKept: await page.evaluate(() => FOCA.state.launch.targets.map(t => t.v)) });
  // Passive profile.
  await tap('[data-act="la-prof:passive"]', 'Passive profile');
  const st = await page.locator('#la-start').boundingBox(); log.push({ startBtnY: Math.round(st.y), H: 852 });
  await shot('07_new_passive');
  await tap('#la-start', 'Start scan');
  log.push({ after_start: await cur(), project: await page.evaluate(() => FOCA.project.name), scan: await page.evaluate(() => ({ running: FOCA.scan.running, active: FOCA.scan.active, profile: FOCA.scan.profile, target: FOCA.scan.target, egress: FOCA.scan.egress })) });
  await shot('08_overview_after_start');
  // Run the scan to completion.
  await page.evaluate(() => FOCA.scanDemo.ff(400)); await page.waitForTimeout(500);
  await shot('09_overview_done');
  // Switch to the active phase.
  const fab = await page.locator('#fab.show').count(); log.push({ fab_visible: fab });
  await tap('#nav [data-tab="/p/overview"]', 'tap current Overview tab (refresh?)');
  log.push({ fab_after_same_tab: await page.locator('#fab.show').count() });
  await tap('#nav [data-tab="/p/findings"]', 'walk: Findings tab');
  await tap('#nav [data-tab="/p/overview"]', 'walk: Overview tab');
  log.push({ fab_after_roundtrip: await page.locator('#fab.show').count() });
  await tap('#fab', 'FAB New scan');
  log.push({ targetsOnReturn: await page.evaluate(() => FOCA.state.launch.targets.map(t => t.v)) });
  await tap('[data-act="la-prof:full"]', 'Full profile');
  await tap('#la-start', 'Start scan: confirm');
  await shot('10_confirm');
  await tap('.la-agree', 'authorization present');
  await page.evaluate(() => { FOCA.page().scrollTop = FOCA.page().scrollHeight; });
  await shot('11_confirm_ready');
  await hold('[data-hold="la-go-active"]', 'Hold to start');
  log.push({ after_active: await cur(), scan: await page.evaluate(() => ({ running: FOCA.scan.running, active: FOCA.scan.active, profile: FOCA.scan.profile, egress: FOCA.scan.egress })), activebar: await page.evaluate(() => document.querySelector('#activebar').classList.contains('show')) });
  await shot('12_after_active');
  await tap('#mini', 'mini-panel');
  await shot('13_scan_screen');
  log.push({ total_taps: taps });
};
