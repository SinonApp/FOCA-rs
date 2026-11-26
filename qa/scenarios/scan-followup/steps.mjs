// Follow-up run of chosen items (demo backend): a queued restart of one search source runs only
// Search and the document pipeline, the other stages show "Not selected"; a queued brute force
// step runs only the Network stage with that step; the stopped view keeps the selection.
// qa/shoot.sh --routes none --w 393 --out $PWD/qa/out/scan-followup --steps $PWD/qa/scenarios/scan-followup/steps.mjs
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
    await wait(400);
  };
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => {
    await wait(250);
    await page.screenshot({ path: `${out}/scan-followup_${n}_${tag}.png` });
  };
  // One core step while the demo timer stays paused.
  const step = n =>
    ev(n => {
      FOCA.api.scan_resume();
      window.FOCA_DEMO_BACKEND._ff(n);
      FOCA.api.scan_pause();
    }, n);
  const status = () => ev(() => FOCA.api.scan_status());
  const toStage = async id => {
    for (let k = 0; k < 60 && (await status()).stage !== id; k++) await step(1);
  };
  const open = async () => {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href);
    await wait(400);
    await ev(() => FOCA.api.demo_reset());
    await wait(150);
    await ev(() => FOCA.api.terms_accept("1"));
    await ev(() => FOCA.api.project_open("contoso"));
    await wait(200);
  };
  const overflow = () =>
    ev(() => {
      const p = FOCA.page() || document.body;
      return Math.max(document.documentElement.scrollWidth - innerWidth, p.scrollWidth - p.clientWidth);
    });
  const stageRow = id =>
    ev(id => {
      const el = document.querySelector(`#scn-st-${id}`);
      return el ? { cls: el.className, text: el.textContent.replace(/\s+/g, " ").trim() } : null;
    }, id);
  // Runs the paused demo scan to its end, recording every stage it entered.
  const runToEnd = async () => {
    const seen = new Set();
    for (let k = 0; k < 120; k++) {
      const s = await status();
      if (!s.running) break;
      seen.add(s.stage);
      await step(1);
    }
    return [...seen];
  };

  // ---- a full scan queues a restart of Startpage after the search stage ----
  await open();
  await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "full" }));
  await ev(() => FOCA.api.scan_pause());
  await go("/p/scan");
  await toStage("network");
  const q = await ev(() => FOCA.api.scan_control("source", "startpage", "restart"));
  ok("restart of a search source after its stage is queued", q && q.state === "queued", q);
  await runToEnd();
  await go("/p/scan");
  const note = await ev(() => {
    const el = document.querySelector(".scn-fup-st");
    return el ? el.textContent.trim() : "";
  });
  ok(
    "follow-up banner names only the stages that will run",
    /Поиск, Загрузка, Извлечение метаданных, Анализ, Отчёт/.test(note) && !/Сеть|Порты|Разведка/.test(note),
    note,
  );
  ok("no horizontal overflow on the finished card", (await overflow()) <= 1, await overflow());
  await shot("banner");

  // ---- the follow-up runs Search + documents only ----
  await ev(() => document.querySelector('[data-act="scan-followup"]').click());
  await wait(400);
  await ev(() => FOCA.api.scan_pause());
  const s1 = await status();
  ok(
    "follow-up passes the chosen items to the core",
    JSON.stringify(s1.only) === JSON.stringify(["source:startpage"]),
    s1.only,
  );
  ok(
    "follow-up runs Search and the document pipeline only",
    JSON.stringify(s1.stages) === JSON.stringify(["search", "download", "meta", "analysis", "report"]),
    s1.stages,
  );
  await go("/p/scan");
  for (const id of ["network", "ports", "recon", "fuzz"]) {
    const r = await stageRow(id);
    ok(`${id}: shown as not selected`, r && /is-sel/.test(r.cls) && /Не выбран/.test(r.text), r);
  }
  const head = await ev(() => document.querySelector("#scn-hd").textContent.replace(/\s+/g, " "));
  ok("header counts only the selected stages", /этап 1 из 5/.test(head), head);
  const ctr = await ev(() => (document.querySelector("#scn-st-search .scn-st-m") || {}).textContent || "");
  const n = +((ctr.match(/\/\s*(\d+)/) || [])[1] || 99);
  ok("search counter counts only the queried sources", n > 0 && n < 5, ctr);
  const subs = await ev(() => (FOCA.scan.sources.find(x => x.id === "subdomains") || {}).status);
  ok("subdomain source is off in this run", subs === "off", subs);
  ok("no horizontal overflow on the narrowed run", (await overflow()) <= 1, await overflow());
  await shot("narrowed");
  for (const [lang, want] of [
    ["en", /Not selected/],
    ["uk", /Не вибрано/],
  ]) {
    await ev(l => FOCA.i18n.setLang(l), lang);
    await wait(250);
    await go("/p/scan");
    const r = await stageRow("network");
    ok(`${lang}: not selected pill is translated`, r && want.test(r.text), r);
    if (lang === "en") await shot("narrowed_en");
  }
  await ev(() => FOCA.i18n.setLang("ru"));
  await wait(200);
  const seen = await runToEnd();
  ok(
    "the run never entered a stage outside the selection",
    seen.every(x => ["search", "download", "meta", "analysis", "report"].includes(x)),
    seen,
  );
  const rec = await ev(() => FOCA.api.project_snapshot("contoso").then(s => s.scans[s.scans.length - 1]));
  ok(
    "stored record names the selection",
    rec && JSON.stringify(rec.only) === JSON.stringify(["source:startpage"]) && rec.stages.length === 5,
    rec && { only: rec.only, stages: rec.stages },
  );

  // ---- a brute force step alone: Network with that step only, then stop ----
  await open();
  await ev(() =>
    FOCA.api.scan_start({ project: "contoso", profile: "std", only: ["step:brute"], from_stage: "network" }),
  );
  await ev(() => FOCA.api.scan_pause());
  await go("/p/scan");
  const s2 = await status();
  ok(
    "step follow-up runs Network and the report only",
    JSON.stringify(s2.stages) === JSON.stringify(["network", "report"]) && s2.stage === "network",
    s2,
  );
  const ids = new Set();
  for (let k = 0; k < 20; k++) {
    await step(1);
    const id = await ev(() => (FOCA.scan.substep || {}).id);
    if (id) ids.add(id);
  }
  ok("only the brute force sub-step runs", [...ids].every(x => x === "brute") && ids.has("brute"), [...ids]);
  const search = await stageRow("search");
  ok("search shown as not selected", search && /is-sel/.test(search.cls), search);
  await ev(() => FOCA.api.scan_stop({ reason: "user" }));
  await wait(300);
  await go("/p/scan-stopped/user");
  const stopped = await ev(() =>
    [...document.querySelectorAll(".scn-steps .scn-step")].map(x => x.className.replace("scn-step is-", "")),
  );
  ok(
    "stopped view marks the stages outside the selection",
    stopped[0] === "sel" && stopped[4] === "cut" && stopped[8] === "none",
    stopped,
  );
  ok("no horizontal overflow on the stopped view", (await overflow()) <= 1, await overflow());
  await shot("stopped");

  console.log(`${oks} OK, ${fails} FAIL`);
};
