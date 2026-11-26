// Screenshots of key screens for visual review (project wizard, confirmations, finding card, preflight, draft).
export default async (page, { out, prep }) => {
  const sfx = await page.evaluate(() => `${innerWidth}_fs${getComputedStyle(document.documentElement).getPropertyValue("--fs").trim() || 1}_${document.documentElement.dataset.theme}`);
  const go = async r => { await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(250); };
  const ev = (f, a) => page.evaluate(f, a); const wait = ms => page.waitForTimeout(ms);
  const shot = async n => { await wait(350); await page.screenshot({ path: `${out}/v_${n}_${sfx}.png` }); };
  await go("/projects");
  await ev(() => { document.querySelector("#pj-q").value = "acme.ua, 10.1.1.0/24"; document.querySelector("#pj-new").dispatchEvent(new Event("submit", { cancelable: true })); }); await wait(300);
  await ev(() => { const i = FOCA.page().querySelector("#la-pclient"); i.value = "ACME"; i.dispatchEvent(new Event("input")); });
  await shot("1_new_project");
  await ev(() => FOCA.actions["la-prof"]("std")); await ev(() => FOCA.actions["la-start"]()); await wait(300);
  await shot("2_confirm_std_new");
  await ev(() => FOCA.back()); await wait(300); await ev(() => FOCA.back()); await wait(400);
  await shot("3_leave_sheet");
  await ev(() => FOCA.actions["la-leave-keep"]()); await wait(500);
  await shot("4_projects_draft");
  await ev(() => FOCA.api.project_open("contoso")); await ev(() => { FOCA.state.launch.leave = true; FOCA.go("/new"); }); await wait(250);
  await ev(() => FOCA.actions["la-prof"]("full")); await ev(() => FOCA.actions["la-start"]()); await wait(350);
  await shot("5_confirm_active");
  await go("/p/finding/1"); await shot("6_finding");
  await ev(() => FOCA.actions["fd-confirm"] ? FOCA.actions["fd-confirm"]() : null); await wait(200); await shot("7_finding_after_confirm");
  await go("/p/overview");
  await ev(() => { FOCA.state.v2.pf = { step: 1, files: [1, 2, 3], cleaned: [] }; FOCA.go("/p/preflight"); }); await wait(300);
  await ev(() => FOCA.actions["v2pf-clean"]("all")); await wait(400); await shot("8_preflight");
};
