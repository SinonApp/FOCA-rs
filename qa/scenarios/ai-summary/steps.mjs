// AI summary (demo backend): themed pickers instead of native <select>, one request per tap,
// cancel, summary history that survives a reload, prompt and placeholders in the UI language.
// qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/ai-summary/steps.mjs [--w 360 --theme light --fs 2]
export default async (page, { W, fsc, theme, out, prep }) => {
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
    await page.screenshot({ path: `${out}/ai-summary_${n}_${tag}.png` });
  };
  const overflow = () =>
    ev(() => {
      const p = FOCA.page() || document.body;
      const shs = [...document.querySelectorAll(".sheet.show")];
      return Math.max(
        document.documentElement.scrollWidth - innerWidth,
        p.scrollWidth - p.clientWidth,
        ...shs.map(sh => sh.scrollWidth - sh.clientWidth),
      );
    });
  const pageText = () => ev(() => (FOCA.page() || document.body).innerText);
  const boot = async () => {
    await page.goto("about:blank");
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href);
    await wait(400);
    if (prep) await prep();
  };
  const errors = [];
  page.on("pageerror", e => errors.push(String(e)));

  await boot();
  await ev(() => FOCA.api.demo_reset());
  await wait(150);
  await ev(() => FOCA.api.terms_accept("1"));
  await ev(() => FOCA.api.key_set("ai", "sk-demo-key-0000"));
  await ev(() => FOCA.api.project_open("contoso"));
  await wait(300);

  // ---- settings: every select is the themed picker ----
  await go("/settings/ai");
  ok("no native <select> on the AI settings screen", (await ev(() => document.querySelectorAll("select").length)) === 0);
  ok(
    "reasoning level, provider and model are picker fields",
    await ev(() => ["#v2ai-th", "#v2ai-p", "#v2ai-m"].every(s => document.querySelector(`button.pick${s}`))),
  );
  await ev(() => document.querySelector("#v2ai-th").scrollIntoView({ block: "center" }));
  await page.click("#v2ai-th");
  await wait(400);
  const pk = await ev(() => {
    const sh = document.querySelector(".pick-sh.show");
    if (!sh) return null;
    const r = sh.getBoundingClientRect();
    const opts = [...sh.querySelectorAll(".pk-o")];
    const first = opts[0].getBoundingClientRect();
    const body = sh.querySelector(".sh-b").getBoundingClientRect();
    return {
      n: opts.length,
      top: r.top,
      firstTop: first.top,
      bodyTop: body.top,
      t: opts.map(o => o.querySelector(".t").textContent),
      s0: (opts[0].querySelector(".s") || {}).textContent || "",
      on: opts.findIndex(o => o.classList.contains("on")),
      title: (sh.querySelector(".sh-h h3") || {}).textContent || "",
      radio: !!opts[0].querySelector(".radio"),
    };
  });
  ok("reasoning picker opens as a themed bottom panel", pk && pk.n === 8 && pk.radio, pk);
  ok("first option is short with a secondary hint", pk && pk.t[0] === "Авто" && /умолчанию модели/.test(pk.s0), pk);
  ok("current value is marked", pk && pk.on === 0, pk);
  ok("panel and its first option are fully on screen", pk && pk.top >= 0 && pk.firstTop >= pk.bodyTop - 1, pk);
  ok("panel title names the setting", pk && /Уровень рассуждений/.test(pk.title), pk);
  ok("no horizontal overflow in the picker", (await overflow()) <= 1, await overflow());
  await shot("picker");
  await page.click('.pick-sh.show [data-pk="5"]');
  await wait(500);
  const saved = await ev(() => ({
    v: (FOCA.db.settings.ai || {}).thinking,
    label: document.querySelector("#v2ai-th .pk-t").textContent,
    open: !!document.querySelector(".pick-sh"),
  }));
  ok("picking saves the value like the old select", saved.v === "high" && saved.label === "Высокий" && !saved.open, saved);
  await wait(300);
  await boot();
  await go("/settings/ai");
  ok(
    "the choice survives a reload",
    await ev(() => FOCA.db.settings.ai.thinking === "high" && document.querySelector("#v2ai-th").value === "high"),
  );
  // Back closes only the picker.
  await page.click("#v2ai-p");
  await wait(350);
  await ev(() => FOCA.back());
  await wait(350);
  ok(
    "Back closes the picker and stays on the screen",
    await ev(() => !document.querySelector(".pick-sh") && FOCA.current() === "/settings/ai"),
  );

  // ---- a picker inside a sheet (findings filter host) keeps the sheet open ----
  await go("/p/findings");
  await ev(() => FOCA.actions["fd-filters"]());
  await wait(400);
  await ev(() => document.querySelector(".sheet.show #fd-host").scrollIntoView({ block: "center" }));
  await page.click(".sheet.show #fd-host");
  await wait(400);
  ok("host picker opens above the filter sheet", (await ev(() => document.querySelectorAll(".sheet.show").length)) === 2);
  await page.click('.pick-sh.show [data-pk="1"]');
  await wait(400);
  const host = await ev(() => ({
    v: document.querySelector("#fd-host").value,
    sheets: document.querySelectorAll(".sheet.show").length,
    btn: document.querySelector("#fd-apply").textContent,
  }));
  ok("filter sheet stays open with the host picked", host.v && host.sheets === 1, host);
  ok("no native <select> anywhere on findings", (await ev(() => document.querySelectorAll("select").length)) === 0);
  await ev(() => FOCA.closeSheet());
  await wait(300);

  // ---- one request per tap ----
  // Count every ai_summarize that reaches the backend (double taps must not add calls).
  await ev(() => {
    const B = window.FOCA_DEMO_BACKEND;
    window.__aiCalls = 0;
    const orig = B.invokeSync.bind(B);
    B.invokeSync = (cmd, args) => {
      if (cmd === "ai_summarize") window.__aiCalls++;
      return orig(cmd, args);
    };
    B._aiDelay(1500);
  });
  await go("/p/ai");
  await ev(() => FOCA.actions["v2ai-step"](1));
  await wait(400);
  await ev(() => document.querySelector('[data-act="v2ai-ok"]').click());
  await wait(150);
  await ev(() => {
    const b = document.querySelector('[data-act="v2ai-send"]');
    for (let i = 0; i < 6; i++) b.click();
    // duplicated events straight to the handler
    FOCA.actions["v2ai-send"]();
    FOCA.actions["v2ai-send"]();
  });
  await wait(100);
  const busy = await ev(() => {
    const b = document.querySelector('[data-act="v2ai-send"]');
    return {
      disabled: b && b.disabled,
      spin: !!(b && b.querySelector(".spin")),
      text: b && b.textContent,
      banner: !!document.querySelector(".v2ai-busy [data-act=v2ai-cancel]"),
      calls: window.__aiCalls,
    };
  });
  ok("send button is disabled with a spinner right after the tap", busy.disabled && busy.spin && /Отправка/.test(busy.text), busy);
  ok("in-flight notice with Cancel is shown", busy.banner, busy);
  ok("ten taps make one request", busy.calls === 1, busy);
  const direct = await ev(() =>
    FOCA.api.ai_summarize("x", {}).then(
      () => "ok",
      e => e.code,
    ),
  );
  ok("the backend rejects a second request for the same project", direct === "busy", direct);
  await shot("busy");
  await wait(2200);
  const res = await ev(() => ({
    out: !!document.querySelector(".v2ai-out"),
    calls: window.__aiCalls,
    list: FOCA_DEMO_BACKEND.invokeSync("ai_summaries_list", { project: "contoso" }),
  }));
  ok("one summary is stored", res.out && res.list.items.length === 1 && res.list.report_id === res.list.items[0].id, res.list);
  await wait(3500);
  await shot("result");

  // ---- cancel ----
  await ev(() => FOCA.actions["v2ai-step"](1));
  await wait(400);
  await ev(() => document.querySelector('[data-act="v2ai-ok"]').click());
  await ev(() => document.querySelector('[data-act="v2ai-send"]').click());
  await wait(200);
  await ev(() => document.querySelector('[data-act="v2ai-cancel"]').click());
  await wait(400);
  const can = await ev(() => ({
    snack: (document.querySelector("#snack") || {}).textContent || "",
    btn: (document.querySelector('[data-act="v2ai-send"]') || {}).disabled,
    n: FOCA_DEMO_BACKEND.invokeSync("ai_summaries_list", { project: "contoso" }).items.length,
  }));
  ok("cancel stops the request and keeps the history", /Запрос отменён/.test(can.snack) && can.btn === false && can.n === 1, can);

  // ---- the summary is kept after leaving the screen and reloading ----
  await ev(() => FOCA.actions["v2ai-send"]());
  await wait(1900);
  await wait(300);
  await boot();
  await ev(() => FOCA.api.project_open("contoso"));
  await go("/p/ai");
  await wait(300);
  const kept = await ev(() => ({
    text: (FOCA.page() || document.body).innerText,
    rows: document.querySelectorAll('.v2ai-hist [data-act^="v2ai-open:"]').length,
    latest: !!document.querySelector(".v2ai-out.done .v2ai-md h4"),
  }));
  ok("latest summary is shown on reopen", kept.latest && /Последняя сводка/.test(kept.text), kept.text.slice(0, 300));
  ok("history lists both summaries with model and language", kept.rows === 2 && /RU/.test(kept.text), kept.rows);
  ok("no em dash on the AI screen", !kept.text.includes("\u2014"));
  ok("no horizontal overflow on the AI screen", (await overflow()) <= 1, await overflow());
  await shot("history");
  // open the older one, put it into the report, then delete it
  await ev(() => document.querySelectorAll('.v2ai-hist [data-act^="v2ai-open:"]')[1].click());
  await wait(400);
  const older = await ev(() => document.querySelector('.sheet.show [data-hold^="v2ai-del:"]').dataset.hold.split(":")[1]);
  await ev(() => document.querySelector('.sheet.show [data-act^="v2ai-rep:"]').click());
  await wait(400);
  ok(
    "Add to report picks the chosen summary",
    await ev(id => FOCA_DEMO_BACKEND.invokeSync("ai_summaries_list", { project: "contoso" }).report_id === id, older),
  );
  await ev(id => FOCA.actions["v2ai-open"](id), older);
  await wait(400);
  await shot("sheet");
  await ev(() =>
    document.querySelector(".sheet.show [data-hold]").dispatchEvent(new PointerEvent("pointerdown", { bubbles: true })),
  );
  await wait(1700);
  const del = await ev(() => FOCA_DEMO_BACKEND.invokeSync("ai_summaries_list", { project: "contoso" }));
  ok("hold-to-delete removes the summary and its report pick", del.items.length === 1 && del.report_id === null, del);

  // ---- UK interface: prompt, placeholders and answer in Ukrainian ----
  await ev(() => FOCA.i18n.setLang("uk"));
  await wait(400);
  await go("/p/ai");
  await ev(() => FOCA.actions["v2ai-step"](1));
  await wait(400);
  const uk = await ev(() => document.querySelector(".v2ai-pre").innerText);
  ok("UK UI gives a Ukrainian prompt", /Пиши українською мовою/.test(uk) && /Проєкт:/.test(uk), uk.slice(0, 300));
  ok("placeholders are language-neutral", /\[CLIENT/.test(uk) && !/\[(КЛИЕНТ|СЕКРЕТ|ФИО)/.test(uk), uk);
  await ev(() => document.querySelector('[data-act="v2ai-ok"]').click());
  await ev(() => document.querySelector('[data-act="v2ai-send"]').click());
  await wait(1900);
  const ukRes = await ev(() => ({
    md: FOCA_DEMO_BACKEND.invokeSync("ai_summaries_list", { project: "contoso" }).items[0],
    hint: (document.querySelector(".v2ai-fh") || {}).textContent || "",
  }));
  ok("summary comes back in Ukrainian", ukRes.md.lang === "uk" && /Ключові ризики/.test(ukRes.md.text), ukRes.md);
  ok("disclaimer shows the neutral placeholder", /\[CLIENT\]/.test(ukRes.hint) && !/КЛИЕНТ/.test(ukRes.hint), ukRes.hint);
  await wait(3000);
  await shot("uk");
  await ev(() => FOCA.i18n.setLang("en"));
  await wait(300);
  await go("/p/ai");
  await ev(() => FOCA.actions["v2ai-step"](1));
  await wait(400);
  const en = await ev(() => document.querySelector(".v2ai-pre").innerText);
  ok("EN UI gives an English prompt", /Write in English/.test(en) && /^Project:/.test(en), en.slice(0, 200));
  await ev(() => FOCA.i18n.setLang("auto"));
  await wait(300);

  ok("no page errors", errors.length === 0, errors);
  console.log(`ai-summary: ${oks} OK, ${fails} FAIL`);
};
