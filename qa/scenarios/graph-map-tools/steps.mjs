// Graph (tap → center + preview, back), map (cluster, point), timeline (year), diff (scan selection),
// plugins (install), AI (preview → streaming → done), intro (swipes, checkbox, PIN), ⋮ menu → Tools.
export default async (page, { out, W, prep }) => {
  const shot = async (n, ms = 380) => { await page.waitForTimeout(ms); await page.screenshot({ path: `${out}/step_${n}_${W}.png` }); };
  const open = async r => { await page.goto('about:blank'); await page.goto(new URL('../../../ui/index.html#', import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };
  const log = [];
  const tapSvg = async sel => { const b = await page.locator(sel).first().boundingBox(); await page.mouse.click(b.x + b.width / 2, b.y + b.height / 2); };

  // Graph.
  await open('/p/graph/person/a.bondar');
  await tapSvg('.v2g-n.v2-t-pc:not(.ctr)');
  await shot('01_graph_recenter_mid', 200);
  await shot('02_graph_peek', 600);
  log.push({ graph_center: await page.evaluate(() => document.querySelector('.v2g-n.ctr')?.dataset.k), sub: await page.evaluate(() => document.querySelector('#tb-s').textContent) });
  await tapSvg('.v2g-n.v2-t-host:not(.ctr)');
  await shot('03_graph_host', 700);
  await page.goBack(); await page.waitForTimeout(300);
  log.push({ after_back1_peek: await page.evaluate(() => !!document.querySelector('.v2-peek.show')) });
  await page.goBack(); await page.waitForTimeout(700);
  log.push({ after_back2_center: await page.evaluate(() => document.querySelector('.v2g-n.ctr')?.dataset.k), route: await page.evaluate(() => FOCA.current()) });
  // Dragging.
  const gb = await page.locator('#v2g-svg').boundingBox();
  await page.mouse.move(gb.x + 60, gb.y + gb.height - 40); await page.mouse.down();
  for (let i = 1; i <= 8; i++) await page.mouse.move(gb.x + 60 + i * 8, gb.y + gb.height - 40 - i * 4);
  await page.mouse.up();
  await page.click('[data-act="v2g-z:in"]'); await page.click('[data-act="v2g-type:doc"]');
  await shot('04_graph_zoom_filter', 600);
  await page.click('.v2g-n.v2g-more, [data-act^="v2g-list:"]'); await shot('05_graph_list_sheet');

  // Map.
  // The 3D globe is a canvas; points and clusters come from S.m3g.hits (screen coordinates).
  await open('/p/map'); await page.waitForTimeout(900);
  const tapHit = async pick => { const h = await page.evaluate(pick); const cb = await page.locator('#v2m-cv').boundingBox(); if (h) await page.mouse.click(cb.x + h.x, cb.y + h.y); return !!h; };
  log.push({ map_cluster: await tapHit(() => FOCA.state.v2.m3g.hits.find(x => x.n > 1)) }); await shot('06_map_cluster_zoom', 1000);
  await page.evaluate(() => { const G = FOCA.db.gps; const i = G.findIndex(g => G.filter(x => Math.abs(x.lat - g.lat) < 0.05 && Math.abs(x.lon - g.lon) < 0.05).length === 1); FOCA.state.v2.m3g.flyTo([Math.max(0, i)], 30); }); await page.waitForTimeout(1000);
  await tapHit(() => FOCA.state.v2.m3g.hits.find(x => x.n === 1)); await page.waitForTimeout(300);
  log.push({ map_point_card: await page.evaluate(() => !!document.querySelector('#v2m-selc')) }); await shot('07_map_point_sheet');

  // Timeline.
  await open('/p/timeline');
  await page.locator('.v2t-bar').nth(8).click(); await shot('08_timeline_year');
  await open('/p/timeline'); await page.click('[data-act="v2t-per:3"]'); await shot('09_timeline_3y');

  // diff
  await open('/p/diff'); await page.click('[data-act="v2d-pick:a"]'); await shot('10_diff_pick');
  await page.click('[data-act="v2d-set:a,0"]'); await page.waitForTimeout(300); await page.click('[data-act="v2d-f:+"]'); await shot('11_diff_new_since_first');

  // Plugins.
  await open('/settings/plugins'); await page.click('[data-act="v2p-install"]'); await page.waitForTimeout(300);
  await page.click('.sheet [data-act="v2p-cons"]'); await shot('12_plugin_install');

  // AI.
  await open('/p/ai'); await page.click('[data-act="v2ai-step:1"]'); await shot('13_ai_preview');
  await page.click('[data-act="v2ai-ok"]'); await page.click('[data-act="v2ai-send"]'); await shot('14_ai_stream', 1500);
  await page.waitForTimeout(9000); await shot('15_ai_done');
  log.push({ ai_done: await page.evaluate(() => FOCA.state.v2.ais.done) });

  // Intro.
  await open('/welcome');
  const vb = await page.locator('#v2w-vp').boundingBox();
  const swipe = async () => { await page.mouse.move(vb.x + vb.width - 40, vb.y + 200); await page.mouse.down(); for (let i = 1; i <= 10; i++) await page.mouse.move(vb.x + vb.width - 40 - i * 24, vb.y + 204); await page.mouse.up(); };
  await swipe(); await shot('16_welcome_2', 500);
  await swipe(); await shot('17_welcome_3', 500);
  await shot('18_welcome_last');
  await page.click('[data-act="v2w-pin"]'); await page.waitForTimeout(300);
  for (const k of ['1', '2']) await page.click(`.v2w-key[data-k="${k}"]`);
  await shot('19_pin_sheet');
  for (const k of ['3', '4']) await page.click(`.v2w-key[data-k="${k}"]`); await page.waitForTimeout(300);
  for (const k of ['1', '2', '3', '4']) await page.click(`.v2w-key[data-k="${k}"]`); await page.waitForTimeout(800);
  log.push({ after_pin_route: await page.evaluate(() => FOCA.current()) });

  // Menu.
  // The PIN set above locks the app on the next start: unlock first.
  await open('/p/overview');
  if ((await page.evaluate(() => FOCA.current())) === '/lock') {
    for (const k of ['1', '2', '3', '4']) await page.click(`[data-act="st-lk:${k}"]`);
    await page.waitForTimeout(800);
  }
  log.push({ after_unlock_route: await page.evaluate(() => FOCA.current()) });
  await page.click('[data-act="menu"]'); await shot('20_menu');
  await page.click('[data-act="v2-tools"]'); await shot('21_tools');
  console.log(JSON.stringify(log));
};
