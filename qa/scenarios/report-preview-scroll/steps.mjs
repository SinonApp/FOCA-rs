// Report preview scrolls to the very end (demo backend, project with many findings): wheel
// scrolling over the sheets moves the page (no nested vertical scroller), the last sheet's footer
// ends inside the viewport above the gesture-bar inset, every included finding row is in the
// tables (no truncated "… N more"), and the same holds at 200 % zoom.
// qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/report-preview-scroll/steps.mjs [--w 360 --theme light --fs 2]
export default async (page, { W, fsc, theme, out, prep, go }) => {
  let fails = 0,
    oks = 0;
  const ok = (name, cond, data) => {
    if (cond) oks++;
    else fails++;
    console.log(`${cond ? "OK  " : "FAIL"} ${name}${!cond && data !== undefined ? " - " + JSON.stringify(data) : ""}`);
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => {
    await wait(300);
    await page.screenshot({ path: `${out}/report-preview-scroll_${n}_${tag}.png` });
  };
  // Scrolls like a user: wheel events over the middle of the sheets until the page stops moving.
  const wheelToEnd = async () => {
    const box = await ev(() => {
      const r = document.querySelector(".rp-scroll").getBoundingClientRect();
      const v = document.querySelector("#viewport").getBoundingClientRect();
      return { x: r.left + r.width / 2, y: (v.top + v.bottom) / 2 };
    });
    await page.mouse.move(box.x, box.y);
    let last = -1;
    for (let i = 0; i < 200; i++) {
      await page.mouse.wheel(0, 900);
      await wait(40);
      const top = await ev(() => FOCA.page().scrollTop);
      if (top === last) break;
      last = top;
    }
    await wait(300);
  };
  const end = () =>
    ev(() => {
      const pg = FOCA.page();
      const sheets = [...document.querySelectorAll(".rp-paper")];
      const last = sheets[sheets.length - 1];
      const pf = last.querySelector(".rp-pf");
      const r = pf.getBoundingClientRect();
      const v = document.querySelector("#viewport").getBoundingClientRect();
      const sc = document.querySelector(".rp-scroll");
      const nums = [...document.querySelectorAll(".rp-paper .rp-tbl tbody tr td:first-child")].map(td => +td.textContent);
      return {
        atBottom: Math.abs(pg.scrollTop + pg.clientHeight - pg.scrollHeight) <= 2,
        footTop: Math.round(r.top),
        footBottom: Math.round(r.bottom),
        vpTop: Math.round(v.top),
        vpBottom: Math.round(v.bottom),
        foot: pf.textContent.replace(/\s+/g, " ").trim(),
        sheets: sheets.length,
        tail: !!last.querySelector(".rp-end"),
        innerScroll: sc.scrollHeight - sc.clientHeight,
        hScroll: sc.scrollWidth - sc.clientWidth,
        nums,
        more: /…\s*(ещё|ще|\d+ more)/.test(document.querySelector(".rp-scroll").textContent),
      };
    });

  await go("/p/report-new");
  await prep();
  await wait(400);
  const included = await ev(() => FOCA.sel.counts().findings.open);
  await ev(() => FOCA.actions["rp-preview"]());
  await wait(900);
  for (const z of [1, 2]) {
    if (z === 2) {
      await ev(() => {
        FOCA.actions["rp-z"]("1");
        FOCA.actions["rp-z"]("1");
      });
      await wait(400);
      await ev(() => (FOCA.page().scrollTop = 0));
    }
    await wheelToEnd();
    const e = await end();
    ok(`zoom ${z}: the page scrolled to the bottom with the wheel`, e.atBottom, e);
    ok(`zoom ${z}: no nested vertical scroller`, e.innerScroll <= 1, e.innerScroll);
    ok(
      `zoom ${z}: last footer fully inside the viewport`,
      e.footTop >= e.vpTop && e.footBottom <= e.vpBottom,
      { footTop: e.footTop, footBottom: e.footBottom, vpTop: e.vpTop, vpBottom: e.vpBottom },
    );
    ok(`zoom ${z}: footer shows the last sheet number`, new RegExp(` ${e.sheets} / ${e.sheets}$`).test(e.foot), e.foot);
    ok(`zoom ${z}: end-of-preview note on the last sheet`, e.tail);
    if (z === 1) {
      ok("many findings: tables continue over several sheets", e.sheets >= 5, e.sheets);
      ok("no truncated table (… N more)", !e.more);
      // rows are numbered 1..n per table without gaps; the findings table holds every open finding
      const runs = [];
      e.nums.forEach(n => (n === 1 ? runs.push([n]) : runs[runs.length - 1].push(n)));
      ok("rows numbered without gaps", runs.every(r => r.every((n, i) => n === i + 1)), runs.map(r => r.length));
      ok("findings table holds every included finding", runs.length > 0 && runs[0].length >= included, { rows: runs[0] && runs[0].length, included });
    } else {
      ok("zoom 2: sheets scroll sideways", e.hScroll > 0, e.hScroll);
    }
    await shot(`z${z}_end`);
  }
  await ev(() => FOCA.actions["rp-z"]("0"));
  console.log(`${oks} OK, ${fails} FAIL`);
};
