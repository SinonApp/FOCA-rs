// Evidence for items not covered by the other regression scenarios and invariants: excluded host notes,
// HIBP, per-project monitoring and "cleaned" status, timeline, entity consistency, software by id, contract.
// qa/shoot.sh --routes /p/overview --out qa/scenarios/regression-round2 --steps $PWD/qa/scenarios/regression-round2/fix.mjs
import fs from "fs";
export default async (page, { out, prep }) => {
  const log = [];
  let fails = 0;
  const ok = (name, cond, data) => {
    if (!cond) fails++;
    log.push([cond ? "OK" : "FAIL", name, data]);
  };
  const go = async r => {
    await page.goto("about:blank");
    await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r);
    await page.waitForTimeout(250);
    await prep();
    await page.waitForTimeout(250);
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).innerText);
  const open = id => ev(i => FOCA.api.project_open(i), id);
  const nav = async r => {
    await ev(r => FOCA.go(r), r);
    await wait(350);
  };
  const shot = async n => {
    await wait(300);
    await page.screenshot({ path: `${out}/regression_round2_${n}.png` });
  };
  try {
    await go("/projects");
    await ev(() => FOCA.api.demo_reset());
    await wait(300);
    await open("contoso");

    // The excluded host note depends on where the data came from.
    const f9 = await ev(() => {
      const f = FOCA.db.findings.find(x => /\.git/.test(x.title));
      return f && { id: f.id, host: f.host, active: !!f.active };
    });
    await ev(h => FOCA.api.scope_set({ excl: FOCA.db.scope.excl.concat(h) }), f9.host);
    await wait(200);
    await nav(`/p/finding/${f9.id}`);
    const t10 = await txt();
    ok(
      'N10: active-module finding card, "Хост исключён после скана … активным модулем", no "к хосту не обращались"',
      f9.active &&
        /Хост исключён после скана/.test(t10) &&
        /активным модулем 19\.11\.2026/.test(t10) &&
        !/не обращались/.test(t10),
      { f9, s: (t10.match(/.{0,40}исключ.{0,90}/) || [""])[0] },
    );
    await shot("n10_finding");
    await nav(`/p/entity/host/${f9.host}`);
    const t10h = await txt();
    ok(
      'N10: host card, "Хост исключён после скана … 19.11.2026", no "К хосту не обращались"',
      /Хост исключён после скана[^\n]*\d\d\.\d\d\.\d{4}/.test(t10h) && !/не обращались/.test(t10h),
      (t10h.match(/В исключениях.{0,160}/) || [""])[0],
    );
    // A host that was really never contacted (passive data only) gets a note saying so.
    const passive = await ev(() => {
      const act = new Set(FOCA.db.findings.filter(f => f.active).map(f => f.host));
      const h = FOCA.db.hosts.find(
        h =>
          !act.has(h.name) &&
          !(h.services || []).length &&
          FOCA.sel.scope.check(h.name).ok &&
          !/^(10|192\.168|172\.)/.test(h.ip || ""),
      );
      return h && h.name;
    });
    if (passive) {
      await ev(h => FOCA.api.scope_set({ excl: FOCA.db.scope.excl.concat(h) }), passive);
      await wait(200);
      await nav(`/p/entity/host/${passive}`);
      ok(
        'N10: host without services or active findings, "К хосту не обращались"',
        /К хосту не обращались/.test(await txt()),
        passive,
      );
    }
    await ev(() => FOCA.api.demo_reset());
    await wait(300);
    await open("contoso");

    // Restarting an active scan takes one tap, without a sheet or confirmation.
    await go("/p/scan");
    await open("contoso");
    const l6 = await ev(() => ({ active: FOCA.sel.lastScan().active, prof: FOCA.sel.lastScan().profile_id }));
    await ev(() => FOCA.actions["scan-restart"]());
    await wait(400);
    const c6 = await ev(() => ({
      path: FOCA.current(),
      run: FOCA.scan.running,
      active: FOCA.scan.active,
      sheet: !!document.querySelector(".sheet.show"),
      hold: !!document.querySelector("[data-hold]"),
    }));
    ok(
      'N6: "Начать заново" for "Полный", immediate: scan with active phase running, no sheet or hold',
      l6.active && c6.run && c6.active && !c6.sheet && !c6.hold && c6.path !== "/confirm-active",
      { l6, c6 },
    );
    await ev(() => FOCA.api.scan_stop("user"));
    await wait(300);
    await ev(() => FOCA.api.demo_reset());
    await wait(300);
    await open("contoso");

    // HIBP: log only for an enabled plugin, key from settings.keys.
    await nav("/settings/plugin/hibp");
    const h1 = await ev(() => ({
      t: FOCA.page().innerText,
      key: ((FOCA.db.settings.keys || {}).hibp || {}).status,
    }));
    ok(
      'N14/#26: HIBP key "Работает" → plugin shows "Указан в «Ключах API»", address check log',
      h1.key === "ok" &&
        /Указан в «Ключах API»/.test(h1.t) &&
        /Проверено адресов/.test(h1.t) &&
        !/без ключа плагин не запустится/.test(h1.t),
      h1.key,
    );
    await nav("/settings/plugins");
    await ev(() => FOCA.actions["v2p-on"]("hibp", document.querySelector('[data-act="v2p-on:hibp"]')));
    await wait(250);
    await nav("/settings/plugin/hibp");
    const h2 = await txt();
    ok(
      'N14: HIBP disabled, log "Плагин выключен", no "Проверено адресов"',
      /Плагин выключен/.test(h2) && !/Проверено адресов/.test(h2),
      (h2.match(/Журнал[\s\S]{0,120}/) || [""])[0],
    );
    await ev(() => FOCA.api.demo_reset());
    await wait(300);
    await open("contoso");

    // Monitoring is per project and survives a reload.
    await nav("/p/monitor");
    const m0 = await txt();
    await ev(() => FOCA.actions["v2mo-mode"]("daily"));
    await wait(250);
    await page.reload();
    await wait(400);
    await prep();
    await open("contoso");
    await nav("/p/monitor");
    const m1 = await ev(() => ({
      on: document.querySelector('[data-act="v2mo-mode:daily"]').classList.contains("on"),
      saved: ((FOCA.db.settings.monitor || {}).contoso || {}).mode,
    }));
    ok(
      "N15: contoso monitoring mode survived reload (settings.monitor[project])",
      m1.on && m1.saved === "daily",
      { m1, before: /Повторные сканы включены/.test(m0) },
    );
    await open("dnipro");
    await nav("/p/monitor");
    const m2 = await ev(() => ({
      off: document.querySelector('[data-act="v2mo-mode:off"]').classList.contains("on"),
      t: FOCA.page().innerText.slice(0, 120),
    }));
    ok(
      "N15: dnipro (no scans) has monitoring off, not shared with contoso",
      m2.off && /Мониторинг выключен/.test(m2.t),
      m2,
    );
    await shot("n15_monitor_dnipro");

    // A document's "cleaned" status is per project, from the snapshot (doc_clean).
    await open("contoso");
    await nav("/p/doc/3");
    await ev(() => FOCA.actions["dd-clean-ok"]("3"));
    await wait(400);
    // Cleaning opens the before/after screen; the mark is checked back on the document card.
    await ev(() => {
      if (FOCA.current() === "/clean/result") FOCA.back();
    });
    await wait(300);
    const c1 = await ev(() => ({
      t: FOCA.page().innerText,
      cl: (FOCA.db.docs.find(d => d.id === 3) || {}).cleaned,
    }));
    ok(
      "N15: contoso document cleaning, via doc_clean, mark on the card",
      !!c1.cl && /Метаданные очищены/.test(c1.t),
      c1.cl,
    );
    await page.reload();
    await wait(400);
    await prep();
    await open("contoso");
    await nav("/p/doc/3");
    ok('N15: "очищен" mark survived reload', /Метаданные очищены/.test(await txt()));
    await open("logistics");
    await nav("/p/doc/3");
    const c2 = await ev(() => ({
      t: FOCA.page().innerText,
      cl: (FOCA.db.docs.find(d => d.id === 3) || {}).cleaned,
    }));
    ok(
      "N15: document with the same id in another project not marked cleaned",
      !c2.cl && !/Метаданные очищены|Очищен/.test(c2.t),
      c2.cl,
    );

    // Timeline: percentages from data and working hours from settings.
    await open("contoso");
    await ev(() => FOCA.api.settings_set({ work_hours: { from: 9, to: 18, tz: "UTC+2" } }));
    await wait(200);
    await nav("/p/timeline");
    const tl = await ev(() => {
      const docs = FOCA.sel.timeline().docs;
      let wk = 0,
        work = 0;
      docs.forEach(d => {
        const [dd, mm, yy] = d.created.slice(0, 10).split(".").map(Number);
        const wd = (new Date(yy, mm - 1, dd).getDay() + 6) % 7;
        const h = +d.created.slice(11, 13);
        if (wd >= 5) wk++;
        else if (h >= 9 && h < 18) work++;
      });
      return {
        n: docs.length,
        wk: Math.round((wk / docs.length) * 100),
        work: Math.round((work / docs.length) * 100),
        t: FOCA.page().innerText,
      };
    });
    ok(
      'N16: "Рабочие часы 9-18": from settings.work_hours, percentage from data',
      new RegExp(`Рабочие часы 9-18[^\\n]*[-:] ${tl.work}%`).test(tl.t),
      { work: tl.work, s: (tl.t.match(/Рабочие часы.{0,60}/) || [""])[0] },
    );
    ok(
      'N16: "Выходные": share of weekend documents from data (no day substitution)',
      new RegExp(`Выходные[-:]? ${tl.wk}%`).test(tl.t) && !/7-16 UTC/.test(tl.t),
      { wk: tl.wk, s: (tl.t.match(/Выходные.{0,30}/) || [""])[0] },
    );
    await shot("n16_timeline");

    // SRV-SQL02: computer and host cards agree; graph via a direct link.
    await nav("/p/entity/pc/SRV-SQL02");
    const pc = await txt();
    await nav("/p/entity/host/SRV-SQL02");
    const hs = await txt();
    const num = (t, k) => {
      const m = t.match(new RegExp(k + "\\s*\\n?\\s*(\\d+|-|-)"));
      return m ? m[1] : null;
    };
    ok(
      'N19: "Находок" matches on PC card and SRV-SQL02 host',
      num(pc, "Находок") && num(pc, "Находок") === num(hs, "Находок") && !["-", "-"].includes(num(pc, "Находок")),
      { pc: num(pc, "Находок"), host: num(hs, "Находок") },
    );
    ok(
      'N19: "Где встречается" for SRV-SQL02: from source (AXFR/connection string), not "LastModifiedBy, Company…"',
      !/LastModifiedBy, Company/.test(pc) && /AXFR|строк/i.test(pc),
      (pc.match(/Поля.{0,80}/) || [""])[0],
    );
    ok(
      'N19: host banner not "найден в метаданных документов" when source is AXFR',
      !/найден в метаданных документов/.test(hs),
      (hs.match(/Внутренний хост.{0,120}/) || [""])[0],
    );
    await go("/p/graph/host/SRV-SQL02");
    const g = await txt();
    ok('N19: graph via direct link, not "Все типы скрыты"', !/Все типы скрыты/.test(g), g.slice(0, 120));

    // Software by id; another project's overview during a scan.
    await go("/p/entity/software/word2013");
    ok(
      "N20: /p/entity/software/word2013 opens by id",
      !/Не найдено/.test(await txt()) && /Word/.test(await txt()),
    );
    await go("/projects");
    await open("contoso");
    await ev(() => FOCA.actions["scan-start"]({ profile: "passive" }));
    await wait(300);
    await open("logistics");
    await ev(() => FOCA.reset(["/projects", "/p/overview"]));
    await wait(400);
    const ov = await ev(() => ({
      t: FOCA.page().innerText,
      other: !!FOCA.page().querySelector(".ov-other"),
      spinCard: !!FOCA.page().querySelector('[data-act="go:/p/scan"] .pbar'),
    }));
    ok(
      'N20: logistics Overview during contoso scan, no foreign "Этап…" card, "Идёт скан проекта «…»" badge',
      ov.other && !ov.spinCard && /Идёт скан проекта/.test(ov.t),
      { other: ov.other, spinCard: ov.spinCard },
    );
    await shot("n20_overview_other");
    await ev(() => FOCA.actions["scan-open-project"]());
    await wait(400);
    ok(
      'N20: "Открыть проект" switches to the project of the running scan',
      await ev(
        () => FOCA.project.id === "contoso" && !!FOCA.page().querySelector('[data-act="go:/p/scan"] .pbar'),
      ),
    );
    await ev(() => FOCA.api.scan_stop("user"));
    await wait(200);

    // Contract and roadmap (static checks).
    const api = fs.readFileSync(new URL("../../../docs/API.md", import.meta.url), "utf8"),
      rm = fs.readFileSync(new URL("../../../docs/ROADMAP.md", import.meta.url), "utf8");
    ok(
      "C8: API.md types include Settings.net.ua_custom, KeyStatus.kind/optional, Doc.title",
      /ua_custom/.test(api) &&
        /kind\?: "url"/.test(api) &&
        /optional\?: bool/.test(api) &&
        /Doc \{[^}]*title/.test(api),
    );
    ok(
      "#37: ROADMAP records F-16 (RDAP/whois), F-21 Roles/Vulnerabilities (adapted), I-2",
      /F-16/.test(rm) && /RDAP/.test(rm) && /Roles\/Vulnerabilities[^\n]*F-21/.test(rm) && /`I-2`/.test(rm),
    );
    ok(
      "#38: ROADMAP, local / on-device AI models dropped, Ctrl+K command palette (I-26) dropped",
      /✖ \*\*Local \/ on-device AI models\*\*/.test(rm) && /`Ctrl\+K` command palette \(`I-26`\)/.test(rm),
    );
  } catch (e) {
    fails++;
    log.push(["FAIL", "exception", String((e && e.stack) || e).slice(0, 500)]);
  }
  try {
    fs.writeFileSync(
      `${out}/regression_round2_fix.json`,
      JSON.stringify({ ok: log.length - fails, fail: fails, log }, null, 1),
    );
  } catch (e) {}
  console.error(
    log
      .map(l => `${l[0]} ${l[1]}${l[0] === "FAIL" ? " " + JSON.stringify(l[2] ?? "").slice(0, 400) : ""}`)
      .join("\n"),
  );
  console.error(`regression-round2: ${log.length - fails} OK, ${fails} FAIL`);
};
