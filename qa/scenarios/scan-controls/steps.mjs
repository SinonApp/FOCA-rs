// Scan screen: network sub-step progress, per-stage / per-source / per-step controls, slow DNS warning
// and the captcha state after a passed verification (demo backend).
// qa/shoot.sh --routes none --w 393 --out $PWD/qa/out/scan-controls --steps $PWD/qa/scenarios/scan-controls/steps.mjs
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
    await page.screenshot({ path: `${out}/scan-controls_${n}_${tag}.png` });
  };
  // One core step while the demo timer stays paused.
  const step = n =>
    ev(n => {
      FOCA.api.scan_resume();
      window.FOCA_DEMO_BACKEND._ff(n);
      FOCA.api.scan_pause();
    }, n);
  const stageId = () => ev(() => FOCA.api.scan_status().then(s => s.stage));
  const toStage = async id => {
    for (let k = 0; k < 60 && (await stageId()) !== id; k++) await step(1);
  };
  const start = async (profile = "std") => {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href);
    await wait(400);
    await ev(() => FOCA.api.demo_reset());
    await wait(150);
    await ev(() => FOCA.api.terms_accept("1"));
    await ev(() => FOCA.api.project_open("contoso"));
    await wait(200);
    await ev(p => FOCA.api.scan_start({ project: "contoso", profile: p }), profile);
    await ev(() => FOCA.api.scan_pause());
    await go("/p/scan");
  };
  const overflow = () =>
    ev(() => {
      const p = FOCA.page() || document.body;
      return Math.max(document.documentElement.scrollWidth - innerWidth, p.scrollWidth - p.clientWidth);
    });

  // ---- network sub-steps: the running stage shows the current sub-step with a counter ----
  await start("std");
  await toStage("network");
  await step(2);
  await wait(300);
  const sub = await ev(() => {
    const el = document.querySelector("#scn-st-network .scn-sub");
    return el ? el.textContent.trim() : null;
  });
  ok("network stage shows the running sub-step", !!sub, sub);
  ok("sub-step has a done/total counter", /\d+\s*\/\s*[\d\s  ,.]+/.test(sub || ""), sub);
  const st = await ev(() => FOCA.api.scan_status());
  ok("scan_status mirrors the sub-step", st.substep && st.substep.stage === "network", st.substep);
  ok("no horizontal overflow", (await overflow()) <= 1, await overflow());
  await shot("substep");

  // ---- slow DNS: warning + "Skip brute force" on the brute force sub-step ----
  for (let k = 0; k < 20; k++) {
    const id = await ev(() => (FOCA.scan.substep || {}).id);
    if (id === "brute") break;
    await step(1);
  }
  await wait(300);
  const slow = await ev(() => {
    const el = document.querySelector("#scn-st-network .scn-slow");
    const b = document.querySelector('[data-act="scan-skip-step:brute"]');
    return { text: el ? el.textContent.trim() : null, btn: !!b };
  });
  ok("slow DNS warning is shown under the brute force sub-step", /VPN/.test(slow.text || ""), slow);
  ok("'Skip brute force' button is visible", slow.btn, slow);
  ok("no horizontal overflow with the slow DNS warning", (await overflow()) <= 1, await overflow());
  await shot("slow_dns");
  await ev(() => document.querySelector('[data-act="scan-skip-step:brute"]').click());
  await wait(300);
  const after = await ev(() => ({
    sub: FOCA.scan.substep,
    btn: !!document.querySelector('[data-act="scan-skip-step:brute"]'),
  }));
  ok("brute force skipped: the button disappears", !after.btn, after);
  await step(3);
  const st2 = await ev(() => FOCA.api.scan_status());
  ok(
    "brute force does not come back after the skip",
    !st2.substep || st2.substep.id !== "brute",
    st2.substep,
  );

  // ---- per-stage / per-source / per-step controls ----
  await start("std");
  await toStage("network");
  await step(1);
  await wait(300);
  const btns = await ev(() =>
    [...document.querySelectorAll(".scn-cbtn")].map(b => {
      const r = b.getBoundingClientRect();
      return { act: b.dataset.act, w: r.width, h: r.height, label: b.getAttribute("aria-label") };
    }),
  );
  const has = a => btns.some(b => b.act === a);
  ok(
    "running stage: pause / skip / restart buttons",
    ["pause", "skip", "restart"].every(a => has(`scan-ctl:stage|network|${a}`)),
    btns.map(b => b.act),
  );
  ok("finished stage: restart button", has("scan-ctl:stage|search|restart"));
  ok("future stage: skip button", has("scan-ctl:stage|ports|skip") || has("scan-ctl:stage|recon|skip"));
  ok(
    "control buttons have labels",
    btns.every(b => b.label && b.label.length > 3),
    btns.filter(b => !b.label),
  );
  ok(
    "control buttons are at least 44×44",
    btns.every(b => b.w >= 44 && b.h >= 44),
    btns.filter(b => b.w < 44 || b.h < 44),
  );
  ok("no horizontal overflow with controls", (await overflow()) <= 1, await overflow());
  await shot("controls");
  // hold the network stage: the core does not move it
  await ev(() => document.querySelector('[data-act="scan-ctl:stage|network|pause"]').click());
  await wait(200);
  const p0 = await ev(() => FOCA.api.scan_status().then(s => s.progress));
  await step(3);
  const s1 = await ev(() => FOCA.api.scan_status());
  ok("held stage does not advance", s1.progress === p0 && s1.held.includes("stage:network"), s1);
  ok(
    "held stage shows a resume button",
    await ev(() => !!document.querySelector('[data-act="scan-ctl:stage|network|resume"]')),
  );
  await ev(() => document.querySelector('[data-act="scan-ctl:stage|network|resume"]').click());
  await wait(200);
  await step(1);
  const s2 = await ev(() => FOCA.api.scan_status());
  ok("resumed stage advances", s2.progress > p0 && !s2.held.includes("stage:network"), s2);
  // restart of a finished stage is queued; the finished card offers a follow-up run
  await ev(() => document.querySelector('[data-act="scan-ctl:stage|search|restart"]').click());
  await wait(200);
  const s3 = await ev(() => FOCA.api.scan_status());
  ok("restart of a finished stage is queued", (s3.followup || []).includes("stage:search"), s3.followup);
  await step(80);
  await wait(400);
  await go("/p/scan");
  const fup = await ev(() => !!document.querySelector('[data-act="scan-followup"]'));
  ok("finished card offers 'Re-run queued'", fup);
  await shot("followup");
  if (fup) {
    await ev(() => document.querySelector('[data-act="scan-followup"]').click());
    await wait(400);
    const s4 = await ev(() => FOCA.api.scan_status());
    ok("follow-up run starts at the queued stage", s4.running && s4.stage === "search", s4);
    await ev(() => FOCA.api.scan_stop({ reason: "user" }));
  }

  // ---- captcha passed after the search stage: no second button, correct state, localized toast ----
  for (const lang of ["ru", "en"]) {
    await start("passive");
    await ev(l => FOCA.i18n.setLang(l), lang);
    await wait(200);
    await toStage("download");
    await go("/p/scan");
    await ev(() => {
      FOCA.api.platform_verify_search = async () => ({ ok: true });
      const sp = FOCA.scan.sources.find(s => s.id === "startpage");
      Object.assign(sp, {
        status: "blocked",
        verifyUrl: "https://www.startpage.com/",
        verifyDone: false,
        retryAsked: false,
      });
      FOCA.render(true);
    });
    await wait(300);
    const before = await ev(() => !!document.querySelector('[data-act="scan-verify-src:startpage"]'));
    ok(`${lang}: blocked Startpage offers 'Pass the check'`, before);
    await ev(() => document.querySelector('[data-act="scan-verify-src:startpage"]').click());
    await wait(500);
    const row = await ev(() => {
      const r = document.querySelector("#scn-src-startpage");
      return {
        text: r ? r.textContent : "",
        verifyBtn: !!document.querySelector('[data-act="scan-verify-src:startpage"]'),
        restart: !!document.querySelector('[data-act="scan-ctl:source|startpage|restart"]'),
        snack: (document.querySelector("#snack") || {}).textContent || "",
      };
    });
    ok(`${lang}: the 'Pass the check' button is gone after passing`, !row.verifyBtn, row);
    ok(`${lang}: restart control is offered`, row.restart, row);
    const want = lang === "en" ? /next scan or after restarting/ : /следующем скане или после перезапуска/;
    ok(
      `${lang}: source card says the check applies on the next scan / restart`,
      want.test(row.text),
      row.text,
    );
    ok(
      `${lang}: toast in the UI language`,
      want.test(row.snack) && (lang !== "en" || !/[А-Яа-я]/.test(row.snack)),
      row.snack,
    );
    if (lang === "en") await shot("verified_en");
    await ev(() => document.querySelector('[data-act="scan-ctl:source|startpage|restart"]').click());
    await wait(200);
    const st = await ev(() => FOCA.api.scan_status());
    ok(
      `${lang}: restart after the search stage is queued`,
      (st.followup || []).includes("source:startpage"),
      st.followup,
    );
    await ev(() => FOCA.api.scan_stop({ reason: "user" }));
    await ev(() => FOCA.i18n.setLang("ru"));
  }

  // ---- URL target: brute force and permutations are skipped with a reason and a hint ----
  await start("std");
  await toStage("network");
  await ev(() => {
    const reason = "пропущено: цель задана как URL (contoso.example), поддомены вне скоупа";
    const msg = { code: "sub.url_target", params: { domain: "contoso.example" } };
    for (const id of ["brute", "permute"])
      FOCA.emit("scan", {
        type: "substep",
        scan_id: FOCA.scan.scanId,
        stage: "network",
        id,
        state: "skipped",
        done: 0,
        total: 0,
        reason,
        reason_msg: msg,
      });
    FOCA.render(true);
  });
  for (const lang of ["ru", "en", "uk"]) {
    await ev(l => FOCA.i18n.setLang(l), lang);
    await wait(250);
    await go("/p/scan");
    const t = await ev(() => {
      const el = document.querySelector("#scn-st-network");
      return el ? el.textContent.replace(/\s+/g, " ") : "";
    });
    const want = {
      ru: [
        /Перебор поддоменов, Перестановки имён: пропущено: цель задана как URL \(contoso\.example\)/,
        /Добавьте домен целью/,
      ],
      en: [
        /Subdomain brute force, Name permutations: skipped: the target is a URL/,
        /Add the domain as a target/,
      ],
      uk: [/піддомени поза скоупом/, /Додайте домен ціллю/],
    }[lang];
    ok(`${lang}: skipped sub-steps show the reason`, want[0].test(t), t);
    ok(`${lang}: hint to add the domain as a target`, want[1].test(t), t);
    ok(`${lang}: no horizontal overflow`, (await overflow()) <= 1, await overflow());
    if (lang === "en") await shot("url_target_en");
  }
  // ---- search stage: download queue summary with the out-of-scope counter ----
  await ev(() => {
    FOCA.emit("scan", {
      type: "substep",
      scan_id: FOCA.scan.scanId,
      stage: "search",
      id: "queue",
      state: "done",
      done: 0,
      total: 8,
      reason: "в загрузку 0 из 8 (вне скоупа 6, уже известны 1, другой тип 1)",
      reason_msg: {
        code: "search.queue",
        params: { added: "0", found: "8", oos: "6", known: "1", other: "1" },
      },
    });
    FOCA.render(true);
  });
  for (const lang of ["ru", "en"]) {
    await ev(l => FOCA.i18n.setLang(l), lang);
    await wait(250);
    await go("/p/scan");
    const t = await ev(() => {
      const el = document.querySelector("#scn-st-search");
      return el ? el.textContent.replace(/\s+/g, " ") : "";
    });
    const want =
      lang === "en"
        ? /Download queue: queued 0 of 8 \(out of scope 6/
        : /Очередь загрузки: в загрузку 0 из 8 \(вне скоупа 6/;
    ok(`${lang}: search stage shows the queue summary with out-of-scope count`, want.test(t), t);
  }
  await ev(() => FOCA.i18n.setLang("ru"));
  await ev(() => FOCA.api.scan_stop({ reason: "user" }));

  console.log(`${oks} OK, ${fails} FAIL`);
};
