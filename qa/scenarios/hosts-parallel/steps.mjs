// Hosts worked on at once: the "Hosts at once" field in Settings → Network and in the launch wizard
// (settings.net.hosts_parallel, 1-8, default 4), its help article, and the scan screen line
// "Hosts: N running, D done of T" with the running names (the core's `hosts` sub-step; demo backend).
// qa/shoot.sh --routes none --out $PWD/qa/out/hosts-parallel --steps $PWD/qa/scenarios/hosts-parallel/steps.mjs
export default async (page, { W, fsc, theme, out }) => {
  let fails = 0,
    oks = 0;
  const ok = (name, cond, data) => {
    if (cond) oks++;
    else fails++;
    console.log(
      `${cond ? "OK  " : "FAIL"} ${name}${!cond && data !== undefined ? " - " + JSON.stringify(data) : ""}`,
    );
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => {
    await ev(r => FOCA.go(r), r);
    await wait(450);
  };
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => {
    await wait(250);
    await page.screenshot({ path: `${out}/hosts-parallel_${n}_${tag}.png` });
  };
  const overflow = () =>
    ev(() => {
      const p = FOCA.page() || document.body;
      return Math.max(document.documentElement.scrollWidth - innerWidth, p.scrollWidth - p.clientWidth);
    });
  const coreSetting = () => ev(() => FOCA.api.settings_get().then(s => (s.net || {}).hosts_parallel));

  await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href);
  await wait(400);
  await ev(() => FOCA.api.demo_reset());
  await wait(150);
  await ev(() => FOCA.api.terms_accept("1"));
  await ev(() => FOCA.api.project_open("contoso"));
  await wait(200);

  // ---- Settings → Network: the field, its default, range and help ----
  await go("/settings/network");
  await ev(() =>
    document.querySelector('.nf[data-nf="net-hostsParallel"]')?.scrollIntoView({ block: "center" }),
  );
  const field = await ev(() => {
    const el = document.querySelector('.nf[data-nf="net-hostsParallel"]');
    if (!el) return null;
    return {
      label: el.querySelector("label").textContent.trim(),
      value: el.querySelector(".nf-in").value,
      help: !!el.querySelector('[data-act="go:/help/set-hosts-parallel"]'),
    };
  });
  ok("Settings → Network has the 'Hosts at once' field", !!field, field);
  ok("the field shows the default of 4", field && field.value === "4", field);
  ok("the field links its help article", field && field.help, field);
  ok("core default is 4", (await coreSetting()) === 4, await coreSetting());
  await shot("settings");
  // + raises the value and saves it to the core
  await ev(() => document.querySelector('[data-act="nf-step:net-hostsParallel:1"]').click());
  await wait(700);
  ok("+ saves 5 to settings.net.hosts_parallel", (await coreSetting()) === 5, await coreSetting());
  // out of range: 9 is refused with the reason, the stored value stays
  await page.fill("#nf-net-hostsParallel", "9");
  await page.press("#nf-net-hostsParallel", "Enter");
  await wait(500);
  const bad = await ev(() => {
    const e = document.querySelector("#nf-net-hostsParallel-e");
    return e && !e.hidden ? e.textContent.trim() : null;
  });
  ok("9 is refused with a reason", !!bad && /8/.test(bad), bad);
  ok("the stored value stays 5", (await coreSetting()) === 5, await coreSetting());
  ok("no horizontal overflow on Settings → Network", (await overflow()) <= 1, await overflow());
  await ev(() => FOCA.api.settings_set({ net: { hosts_parallel: 3 } }));
  await wait(300);

  // ---- help article ----
  await go("/help/set-hosts-parallel");
  const help = await ev(() => (FOCA.page() || document.body).innerText);
  ok("help article opens", /1-8/.test(help) && /429/.test(help), help.slice(0, 200));

  // ---- launch wizard: the same setting next to threads and requests per second ----
  await ev(() => {
    FOCA.state.launch.leave = true;
    FOCA.go("/new");
  });
  await wait(450);
  if (!(await ev(() => FOCA.state.launch.adv))) await ev(() => FOCA.actions["la-adv"]());
  await wait(300);
  const wiz = await ev(() => {
    const el = document.querySelector('.nf[data-nf="la-net-hosts_parallel"]');
    return el ? el.querySelector(".nf-in").value : null;
  });
  ok("launch wizard shows the shared value (3)", wiz === "3", wiz);

  // ---- scan screen: hosts running now in the ports stage ----
  await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "full" }));
  await ev(() => FOCA.api.scan_pause());
  await go("/p/scan");
  const step = n =>
    ev(n => {
      FOCA.api.scan_resume();
      window.FOCA_DEMO_BACKEND._ff(n);
      FOCA.api.scan_pause();
    }, n);
  for (let k = 0; k < 80; k++) {
    const st = await ev(() => FOCA.api.scan_status());
    if (st.stage === "ports" && st.substep && st.substep.id === "hosts" && st.substep.running.length) break;
    await step(1);
  }
  await wait(400);
  const line = await ev(() => {
    const el = document.querySelector("#scn-sub-hosts");
    const names = document.querySelector(".scn-subhosts");
    return { text: el ? el.textContent.trim() : null, names: names ? names.textContent.trim() : null };
  });
  const st = await ev(() => FOCA.api.scan_status());
  const sub = st.substep || {};
  ok("scan_status carries the hosts sub-step", sub.id === "hosts" && sub.stage === "ports", sub);
  ok("at most 3 hosts run at once", (sub.running || []).length > 0 && sub.running.length <= 3, sub);
  ok(
    "the ports stage shows 'Hosts: N running, D done of T'",
    line.text &&
      new RegExp(`${sub.running.length}\\D+${sub.done}\\D+${sub.total}`).test(line.text.replace(/\s+/g, " ")),
    { line, sub },
  );
  ok("the running host names are listed", !!line.names && line.names.includes(sub.running[0]), line);
  ok("no horizontal overflow with the hosts line", (await overflow()) <= 1, await overflow());
  await ev(() => document.querySelector("#scn-sub-hosts")?.scrollIntoView({ block: "center" }));
  await shot("scan_hosts");
  // the line follows the UI language
  for (const [l, re] of [
    ["en", /^Hosts: \d+ running, \d+ done of \d+$/],
    ["uk", /^Хости: \d+ у роботі, \d+ готово з \d+$/],
  ]) {
    await ev(l => FOCA.i18n.setLang(l), l);
    await wait(600);
    await go("/p/scan");
    const t = await ev(() => {
      const el = document.querySelector("#scn-sub-hosts");
      return el ? el.textContent.trim().replace(/\s+/g, " ") : null;
    });
    ok(`hosts line in ${l}`, re.test(t || ""), t);
  }
  await ev(() => FOCA.i18n.setLang("auto"));
  await wait(300);
  await ev(() => FOCA.api.scan_stop());
  console.log(`${oks} OK, ${fails} FAIL`);
};
