// Demo: live updates during a running scan never disturb browsing.
// - Documents list: scroll position and the first visible row survive live re-renders, also when
//   new documents are inserted above; re-renders wait while the finger is on the screen.
// - Selection mode: selected ids, the top bar and the bottom action bar stay put (no slide-in
//   replay), the floating scan bar is hidden.
// - Overview: the floating scan bar appears only after the scan card scrolls away.
// - Counters: the overview/floating summary and the download stage row show the same queue pair,
//   with the breakdown; the finished stage keeps it.
// - Documents sort: date options order by document date, else discovery time, unknown last; the
//   choice survives live updates.
// qa/shoot.sh --routes none --out $PWD/qa/out/live-refresh --steps $PWD/qa/scenarios/live-refresh/steps.mjs [--w 360 --fs 2]
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = [];
  let fails = 0;
  const ok = (name, cond, data) => {
    if (!cond) fails++;
    log.push([cond ? "OK" : "FAIL", name, data]);
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const live = n =>
    ev(async n => {
      for (let i = 0; i < n; i++) {
        FOCA.emit("db", { kind: "scan" });
        await new Promise(r => setTimeout(r, 420));
      }
    }, n);
  const firstRow = () =>
    ev(() => {
      const p = FOCA.page();
      const top = p.getBoundingClientRect().top;
      const r = [...p.querySelectorAll(".dt-doc")].find(e => e.getBoundingClientRect().bottom > top + 1);
      return r
        ? {
            id: r.dataset.id,
            off: Math.round(r.getBoundingClientRect().top - top),
            y: Math.round(p.scrollTop),
          }
        : null;
    });
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href);
    await wait(400);
    await ev(() => FOCA.api.demo_reset());
    await wait(150);
    await ev(() => FOCA.api.terms_accept("1"));
    await ev(() => FOCA.api.project_open("contoso"));
    await wait(300);
    // Many documents so the list scrolls (demo copies of the existing rows).
    await ev(() => {
      const base = FOCA.db.docs.slice();
      let id = 9000;
      for (let k = 0; k < 3; k++)
        base.forEach(d => FOCA.db.docs.push({ ...d, id: id++, name: `copy${k}_${d.name}`, deleted: false }));
    });
    await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "passive" }));
    await wait(300);
    await ev(() => FOCA.api.scan_pause());
    await wait(200);

    // ---- documents list: scroll kept across live updates ----
    await ev(() => FOCA.reset(["/p/data/docs"]));
    await wait(600);
    await ev(() => {
      const p = FOCA.page();
      p.scrollTop = Math.round((p.scrollHeight - p.clientHeight) / 2);
    });
    await wait(700);
    const before = await firstRow();
    await live(4);
    await wait(700);
    const after = await firstRow();
    ok(
      "docs: scroll position and first visible row kept across live updates",
      before && after && before.id === after.id && Math.abs(before.y - after.y) <= 3,
      { before, after },
    );
    // New documents arrive above (sort: newest first): the row under the user stays in place.
    await ev(() => {
      const d = FOCA.db.docs[0];
      for (let i = 0; i < 3; i++)
        FOCA.db.docs.unshift({
          ...d,
          id: 9900 + i,
          name: `fresh_${i}.pdf`,
          created_at: "2099-01-01T10:0" + i + ":00Z",
          created: "01.01.2099 10:0" + i,
          deleted: false,
        });
    });
    await live(2);
    await wait(700);
    const ins = await firstRow();
    ok(
      "docs: rows inserted above keep the first visible row and its offset",
      ins && ins.id === before.id && Math.abs(ins.off - before.off) <= 3,
      { before, ins },
    );
    // Finger on the screen: the live re-render waits.
    const pg0 = await ev(() => ((window.__pg = FOCA.page()), true));
    await ev(() => window.dispatchEvent(new TouchEvent("touchstart", { bubbles: true })));
    await ev(() => FOCA.emit("db", { kind: "scan" }));
    await wait(300);
    const sameWhileTouch = await ev(() => window.__pg === FOCA.page());
    await ev(() => window.dispatchEvent(new TouchEvent("touchend", { bubbles: true })));
    await wait(1100);
    const renderedAfter = await ev(() => window.__pg !== FOCA.page());
    ok(
      "docs: re-render deferred while touching, done after release",
      pg0 && sameWhileTouch && renderedAfter,
      { sameWhileTouch, renderedAfter },
    );

    // ---- selection mode ----
    await ev(() => FOCA.actions["dd-sel-start"]());
    await wait(500);
    await ev(() => {
      const rows = [...FOCA.page().querySelectorAll(".dt-doc")].slice(0, 3);
      rows.forEach(r => r.click());
    });
    await wait(500);
    const bar = () =>
      ev(() => {
        const b = document.querySelector(".dt-selbar");
        if (!b) return null;
        const r = b.getBoundingClientRect();
        return { y: Math.round(r.top), h: Math.round(r.height), anim: getComputedStyle(b).animationName };
      });
    const b0 = await bar();
    const sel0 = await ev(() => FOCA.state.dataDocs.sel && [...FOCA.state.dataDocs.sel].sort().join());
    await ev(() => {
      const p = FOCA.page();
      p.scrollTop = Math.round((p.scrollHeight - p.clientHeight) / 2);
    });
    await wait(700);
    const y0 = await ev(() => Math.round(FOCA.page().scrollTop));
    await live(3);
    await ev(() => FOCA.emit("db", { kind: "scan" }));
    await wait(120);
    const bMid = await bar();
    await wait(700);
    const b1 = await bar();
    const sel1 = await ev(() => FOCA.state.dataDocs.sel && [...FOCA.state.dataDocs.sel].sort().join());
    const y1 = await ev(() => Math.round(FOCA.page().scrollTop));
    ok(
      "selection: 3 selected ids kept across live updates",
      sel0 && sel0 === sel1 && sel0.split(",").length === 3,
      { sel0, sel1 },
    );
    ok(
      "selection: action bar does not move or replay its slide-in",
      b0 &&
        b1 &&
        bMid &&
        Math.abs(b0.y - b1.y) <= 1 &&
        b0.h === b1.h &&
        Math.abs(bMid.y - b0.y) <= 1 &&
        bMid.anim === "none",
      { b0, bMid, b1 },
    );
    ok("selection: scroll kept", Math.abs(y0 - y1) <= 3, { y0, y1 });
    const miniSel = await ev(() => {
      const m = document.getElementById("mini");
      return m.classList.contains("show") && getComputedStyle(m).display !== "none";
    });
    ok("selection: floating scan bar hidden", !miniSel);
    const n0 = await ev(() => (document.querySelector('[data-act="dd-sel-all"]') || {}).textContent || "");
    await page.screenshot({ path: `${out}/live-refresh_selection_${tag}.png` });
    await ev(() => FOCA.actions["dd-sel-exit"]());
    await wait(300);
    ok("selection: 'select all N' names the current count", /\d/.test(n0), n0);

    // ---- overview: one progress widget at a time ----
    await ev(() => FOCA.reset(["/p/overview"]));
    await wait(600);
    const ov = () =>
      ev(() => ({
        card: !!document.getElementById("ov-scan"),
        mini: document.getElementById("mini").classList.contains("show"),
      }));
    const o1 = await ov();
    ok("overview: scan card at the top, floating bar hidden", o1.card && !o1.mini, o1);
    await page.screenshot({ path: `${out}/live-refresh_overview_top_${tag}.png` });
    await ev(() => {
      const p = FOCA.page();
      p.scrollTop = p.scrollHeight;
      p.dispatchEvent(new Event("scroll"));
    });
    await wait(400);
    const o2 = await ev(() => {
      const c = document.getElementById("ov-scan").getBoundingClientRect(),
        p = FOCA.page().getBoundingClientRect();
      return { away: c.bottom <= p.top, mini: document.getElementById("mini").classList.contains("show") };
    });
    ok("overview: the floating bar appears once the card scrolled away", !o2.away || o2.mini, o2);

    // ---- counters: one queue pair everywhere ----
    await ev(() => FOCA.reset(["/p/scan"]));
    await wait(500);
    await ev(() => {
      const sid = FOCA.scan.scanId;
      FOCA.emit("scan", { type: "stage", scan_id: sid, stage: "download", label: "Загрузка", index: 1 });
      FOCA.emit("scan", {
        type: "progress",
        scan_id: sid,
        progress: 15,
        stage: "download",
        done: 127,
        total: 800,
      });
      FOCA.emit("scan", {
        type: "substep",
        scan_id: sid,
        stage: "download",
        id: "files",
        state: "running",
        done: 127,
        total: 800,
        added: 20,
        docs: 101,
        images: 6,
        failed: 15,
        private: 2,
        duplicates: 9,
        skipped: 0,
      });
    });
    await wait(500);
    const cnt = await ev(() => ({
      summary: FOCA.scan.summary,
      row: (
        document.querySelector('.scn-st[data-stage="download"], #scn-st-download') || document.body
      ).textContent.replace(/\s+/g, " "),
      mini: document.getElementById("mi-s").textContent,
    }));
    const pair = /127\/800/;
    ok(
      "counters: summary, floating bar and stage row share the queue pair",
      pair.test(cnt.summary) &&
        pair.test(cnt.mini) &&
        pair.test(cnt.row) &&
        !/131\/131|800\/800/.test(cnt.summary),
      cnt,
    );
    ok(
      "counters: stage row has the breakdown and the queue growth",
      /в документах 101/.test(cnt.row) &&
        /изображений 6/.test(cnt.row) &&
        /недоступно 17/.test(cnt.row) &&
        /дубликатов 9/.test(cnt.row) &&
        /\+20 новых в очереди/.test(cnt.row),
      cnt.row.slice(0, 400),
    );
    await page.screenshot({ path: `${out}/live-refresh_counters_${tag}.png` });
    // The stage ends: the row keeps the last queue pair.
    await ev(() => {
      const sid = FOCA.scan.scanId;
      FOCA.emit("scan", {
        type: "substep",
        scan_id: sid,
        stage: "download",
        id: "files",
        state: "done",
        done: 820,
        total: 820,
        docs: 110,
        images: 6,
        failed: 15,
        private: 2,
        duplicates: 9,
        skipped: 0,
      });
      FOCA.emit("scan", {
        type: "progress",
        scan_id: sid,
        progress: 22,
        stage: "download",
        done: 820,
        total: 820,
      });
      FOCA.emit("scan", {
        type: "stage",
        scan_id: sid,
        stage: "meta",
        label: "Извлечение метаданных",
        index: 2,
      });
    });
    await wait(500);
    const done = await ev(() => document.body.textContent.replace(/\s+/g, " "));
    ok(
      "counters: the finished download stage keeps 820/820 and the breakdown",
      /очередь 820\/820/.test(done) && /в документах 110/.test(done),
      done.slice(done.indexOf("очередь") - 40, done.indexOf("очередь") + 140),
    );

    // ---- documents sort ----
    await ev(() => {
      FOCA.db.docs.forEach((d, i) => {
        if (i % 3 === 0) {
          d.created_at = null;
          d.created = "-";
        }
      });
    });
    await ev(() => FOCA.reset(["/p/data/docs"]));
    await wait(400);
    const order = () =>
      ev(() =>
        [...FOCA.page().querySelectorAll(".dt-doc")]
          .slice(0, 40)
          .map(r => r.dataset.id)
          .join(),
      );
    await ev(() => FOCA.actions["dd-sort"]("date"));
    await wait(400);
    const oNew = await order();
    await ev(() => FOCA.actions["dd-sort"]("date-asc"));
    await wait(400);
    const oOld = await order();
    await ev(() => FOCA.actions["dd-sort"]("name"));
    await wait(400);
    const oName = await order();
    await ev(() => FOCA.actions["dd-sort"]("size"));
    await wait(400);
    const oSize = await order();
    ok("sort: every option changes the order", new Set([oNew, oOld, oName, oSize]).size === 4, {
      oNew: oNew.slice(0, 40),
      oOld: oOld.slice(0, 40),
    });
    await ev(() => FOCA.actions["dd-sort"]("date-asc"));
    await wait(300);
    await live(2);
    await wait(500);
    ok(
      "sort: the choice survives live updates",
      (await order()) === oOld && (await ev(() => FOCA.state.dataDocs.sort)) === "date-asc",
    );
    await ev(() => FOCA.actions["dd-sort"]("name"));
    await wait(400);
    const rowText = await ev(() =>
      [...FOCA.page().querySelectorAll(".dt-doc .s")].map(e => e.textContent).join(" | "),
    );
    ok(
      "sort: documents without their own date show when they were found",
      /найден/.test(rowText) && !/- · ·/.test(rowText),
      rowText.slice(0, 200),
    );
    await ev(() => FOCA.actions["dd-sort"]("date"));
    await ev(() => FOCA.api.scan_stop({ reason: "user" }));
  } catch (e) {
    fails++;
    log.push(["FAIL", "exception", String((e && e.stack) || e).slice(0, 500)]);
  }
  fs.writeFileSync(`${out}/live-refresh_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(
    log
      .map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] ?? "").slice(0, 400) : ""}`)
      .join("\n"),
  );
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
