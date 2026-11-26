// Clearing journals (demo backend): the quick tools log (plain confirm with the count), the project
// request log (all / older than N days / one scan, hold-to-confirm, dry-run counts, running scan
// guard) and the app logs sheet labelled apart from the request log.
// qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/journal-clear/steps.mjs [--w 360 --theme light --fs 2]
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
    await page.screenshot({ path: `${out}/journal-clear_${n}_${tag}.png` });
  };
  const overflow = () =>
    ev(() => {
      const p = FOCA.page() || document.body;
      const sh = document.querySelector(".sheet.show");
      return Math.max(
        document.documentElement.scrollWidth - innerWidth,
        p.scrollWidth - p.clientWidth,
        sh ? sh.scrollWidth - sh.clientWidth : 0,
      );
    });
  const sheet = () =>
    ev(() => {
      const sh = document.querySelector(".sheet.show");
      if (!sh) return null;
      const h = sh.querySelector("[data-hold]");
      return {
        title: (sh.querySelector(".sh-h h3") || {}).textContent || "",
        text: sh.textContent.replace(/\s+/g, " "),
        count: (sh.querySelector("#rlc-n") || {}).textContent || "",
        hold: !!h,
        holdOff: !!(h && h.disabled),
      };
    });
  const snack = () => ev(() => (document.querySelector("#snack") || {}).textContent || "");
  const hold = async () => {
    await ev(() =>
      document
        .querySelector(".sheet.show [data-hold]")
        .dispatchEvent(new PointerEvent("pointerdown", { bubbles: true })),
    );
    await wait(1700);
    await ev(() => document.dispatchEvent(new PointerEvent("pointerup", { bubbles: true })));
    await wait(400);
  };
  const act = async (a, ms = 350) => {
    await page.click(`.sheet.show [data-act="${a}"], .page [data-act="${a}"]`);
    await wait(ms);
  };
  const reqLog = () => ev(() => FOCA.api.request_log_get({ limit: 1e9 }));
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
  await ev(() => FOCA.api.project_open("contoso"));
  await wait(200);

  // ---- quick tools log ----
  await ev(() => FOCA.api.tool_mail_domain({ domain: "contoso.example" }));
  await go("/tools");
  await ev(() => FOCA.actions["tbx-tab"]("log"));
  await wait(400);
  const rows = await ev(() => document.querySelectorAll(".page .list .row").length);
  ok("tools log lists the mail tool requests", rows === 3, rows);
  ok("tools log has a Clear button", await ev(() => !!document.querySelector('[data-act="tbx-log-clear"]')));
  ok("no horizontal overflow on the tools log", (await overflow()) <= 1, await overflow());
  await shot("tools-log");
  await act("tbx-log-clear");
  const ts = await sheet();
  ok("tools log confirm sheet", ts && /Очистить журнал инструментов/.test(ts.title), ts);
  ok("tools log confirm shows the count", ts && /Записей: 3/.test(ts.text), ts && ts.text);
  ok("tools log confirm is a plain button, not hold", ts && !ts.hold, ts);
  ok("no horizontal overflow in the tools log sheet", (await overflow()) <= 1, await overflow());
  await shot("tools-sheet");
  await act("tbx-log-clear-go", 500);
  ok("tools log is empty after clearing", (await ev(() => FOCA.api.tool_log({}))).length === 0);
  ok(
    "tools log shows the empty state",
    await ev(() => !!document.querySelector(".page .empty") && !document.querySelector(".page .list .row")),
  );
  ok("snack confirms the tools log clear", /Журнал инструментов очищен/.test(await snack()), await snack());

  // ---- project request log on the debug screen ----
  const all0 = await reqLog();
  const s1 = all0.filter(r => r.scan_id === "contoso-s1").length;
  const s2 = all0.filter(r => r.scan_id === "contoso-s2").length;
  ok("contoso has request rows of both scans", s1 > 0 && s2 > 0 && s1 + s2 === all0.length, { s1, s2 });
  await go("/settings/debug");
  await ev(() => FOCA.actions["dbg-seg"]("req"));
  await wait(500);
  const labels = await ev(() => document.querySelector(".page").textContent.replace(/\s+/g, " "));
  ok("app logs row is labelled as app logs", /Очистить логи приложения/.test(labels), labels.slice(-600));
  ok("request log row is offered on the Requests tab", /Очистить журнал запросов/.test(labels));
  ok("no horizontal overflow on the Requests tab", (await overflow()) <= 1, await overflow());
  await act("rl-clear", 500);
  let rs = await sheet();
  ok("request log sheet opens", rs && /Очистить журнал запросов/.test(rs.title), rs);
  ok("request log clear is hold-to-confirm", rs && rs.hold && !rs.holdOff, rs);
  ok(
    "count for the whole log comes from a dry run",
    rs && new RegExp(`Будут удалены ${all0.length} запис`).test(rs.count),
    rs && rs.count,
  );
  ok("sheet says findings and reports stay", rs && /Находки, документы и отчёты останутся/.test(rs.text));
  ok("no horizontal overflow in the request log sheet", (await overflow()) <= 1, await overflow());
  await shot("req-sheet");
  // a short tap does nothing
  await ev(() => document.querySelector(".sheet.show [data-hold]").click());
  await wait(300);
  ok("a tap does not clear", (await reqLog()).length === all0.length);
  // older than 30 days: both demo scans are newer
  await act("rlc-mode:older", 450);
  rs = await sheet();
  ok(
    "older than offers 7/30/90 days",
    await ev(() => document.querySelectorAll('.sheet.show [data-act^="rlc-days:"]').length === 3),
  );
  ok("30 days selects nothing and disables the button", rs && /записей нет/.test(rs.count) && rs.holdOff, rs);
  await act("rlc-days:7", 450);
  rs = await sheet();
  ok(
    "7 days selects the older scan",
    rs && new RegExp(`удален[аы]? ${s1} запис`).test(rs.count),
    rs && rs.count,
  );
  await shot("req-older");
  // one scan
  await act("rlc-mode:scan", 450);
  ok(
    "one scan lists the finished scans",
    await ev(() => document.querySelectorAll('.sheet.show [data-act^="rlc-scan:"]').length === 2),
  );
  await act("rlc-scan:contoso-s2", 450);
  rs = await sheet();
  ok("one scan counts that scan", rs && new RegExp(`удален[аы]? ${s2} запис`).test(rs.count), rs && rs.count);
  ok("no horizontal overflow with scan chips", (await overflow()) <= 1, await overflow());
  await shot("req-scan");
  // clear older than 7 days for real
  await act("rlc-mode:older", 300);
  await act("rlc-days:7", 450);
  await hold();
  const left = await reqLog();
  ok("hold clears only the older scan", left.length === s2 && left.every(r => r.scan_id === "contoso-s2"), {
    left: left.length,
    s2,
  });
  ok("sheet closes after clearing", !(await sheet()));
  ok("snack reports the removed count", new RegExp(`${s1} запис`).test(await snack()), await snack());
  ok(
    "Requests tab shows the shorter log",
    await ev(n => document.querySelectorAll(".page .dbg-r").length === n, s2),
  );
  await shot("req-after");

  // ---- app logs sheet is clearly not the request log ----
  await ev(() => FOCA.actions["dbg-clear"]());
  await wait(400);
  const al = await sheet();
  ok("app logs sheet title", al && /Очистить логи приложения\?/.test(al.title), al);
  ok("app logs sheet says the request log stays", al && /журнал запросов не затрагиваются/.test(al.text), al);
  await ev(() => FOCA.closeSheet());
  await wait(300);

  // ---- reports: export sheet of the request log offers clearing, count follows ----
  await go("/p/reports");
  const tile = await ev(() =>
    ([...document.querySelectorAll('[data-act="rp-quick:log"]')][0] || {}).textContent.replace(/\s+/g, " "),
  );
  ok("reports tile counts the shorter log", new RegExp(`${s2} запрос`).test(tile), tile);
  await ev(() => FOCA.actions["rp-quick"]("log"));
  await wait(500);
  ok(
    "request log export sheet offers clearing",
    await ev(() => !!document.querySelector('.sheet.show [data-act="rl-clear"]')),
  );
  await act("rl-clear", 500);
  rs = await sheet();
  ok("clearing opens from the export sheet", rs && /Очистить журнал запросов/.test(rs.title), rs);
  await ev(() => FOCA.closeSheet());
  await wait(300);

  // ---- a running scan: its log cannot be cleared on its own ----
  await ev(() => FOCA.api.project_open("agro"));
  await wait(200);
  await ev(() => FOCA.api.scan_start({ project: "agro", profile: "passive" }));
  await ev(() => FOCA.api.scan_pause());
  await wait(300);
  const runId = await ev(() => FOCA.api.scan_status().then(s => s.scan_id));
  const err = await ev(
    id =>
      FOCA.api.request_log_clear({ scan_id: id }).then(
        () => null,
        e => ({ code: e.code, text: FOCA.coreMsg(e.message, e.message_msg) }),
      ),
    runId,
  );
  ok(
    "clearing the running scan is refused",
    err && err.code === "busy" && /Скан ещё идёт/.test(err.text),
    err,
  );
  await go("/settings/debug");
  await ev(() => FOCA.actions["dbg-seg"]("req"));
  await wait(400);
  await act("rl-clear", 500);
  await act("rlc-mode:scan", 450);
  ok(
    "the running scan is not offered as one scan",
    !(await ev(id => !!document.querySelector(`.sheet.show [data-act="rlc-scan:${id}"]`), runId)),
    runId,
  );
  await ev(() => FOCA.closeSheet());
  await ev(() => FOCA.api.scan_stop("user"));
  await wait(300);

  // ---- English texts ----
  await ev(() => FOCA.i18n.setLang("en"));
  await wait(400);
  await ev(() => FOCA.api.project_open("contoso"));
  await go("/settings/debug");
  await ev(() => FOCA.actions["dbg-seg"]("req"));
  await wait(400);
  await act("rl-clear", 500);
  rs = await sheet();
  ok(
    "EN request log sheet",
    rs && rs.title === "Clear the request log?" && /records? will be deleted/.test(rs.count),
    rs,
  );
  ok("EN sheet has no Cyrillic", rs && !/[\u0400-\u04ff]/.test(rs.text), rs && rs.text);
  await shot("req-sheet-en");
  await ev(() => FOCA.closeSheet());
  await wait(200);
  const en = await ev(() => document.querySelector(".page").textContent);
  ok("EN app logs row", /Clear app logs/.test(en));
  await ev(() => FOCA.i18n.setLang("ru"));
  await wait(300);

  ok("no em dash in the new texts", !JSON.stringify([ts, al, labels, tile]).includes("\u2014"));
  ok("no page errors", errors.length === 0, errors);
  console.log(`${oks} OK, ${fails} FAIL`);
};
