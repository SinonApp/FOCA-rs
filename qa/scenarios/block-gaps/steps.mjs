// Demo: one vertical rhythm for stacked blocks. On every route of qa/routes.txt (plus document
// cards in each state: queued, downloaded but not parsed, parsed) no two adjacent visible blocks
// (cards, lists, notes/banners) are closer than 8 px or overlap.
// qa/shoot.sh --routes none --out $PWD/qa/out/block-gaps --steps $PWD/qa/scenarios/block-gaps/steps.mjs [--w 360 --fs 2 --theme light]
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
  const MIN = 8;
  const routes = fs
    .readFileSync(new URL("../../routes.txt", import.meta.url), "utf8")
    .trim()
    .split(",")
    .filter(r => r && r !== "/lock");
  // Adjacent block siblings stacked vertically (same column) with their gap.
  const tight = () =>
    ev(min => {
      const page = FOCA.page();
      if (!page) return [];
      const isBlock = el => el.matches(".card, .list, .banner");
      const vis = el => {
        const r = el.getBoundingClientRect();
        return r.height > 0 && r.width > 0 && getComputedStyle(el).visibility !== "hidden";
      };
      const bad = [];
      for (const el of page.querySelectorAll(".card, .list, .banner")) {
        const nx = el.nextElementSibling;
        if (!nx || !isBlock(nx) || !vis(el) || !vis(nx)) continue;
        const ps = getComputedStyle(el.parentElement);
        // Grid/row-flex containers lay blocks out side by side or with their own gap.
        if (
          ps.display.includes("grid") ||
          (ps.display.includes("flex") && !ps.flexDirection.startsWith("column"))
        )
          continue;
        const a = el.getBoundingClientRect(),
          b = nx.getBoundingClientRect();
        const sameCol = Math.min(a.right, b.right) - Math.max(a.left, b.left) > 20;
        if (!sameCol) continue;
        const gap = Math.round(b.top - a.bottom);
        if (gap < min)
          bad.push({
            gap,
            a: (el.className || "").toString().slice(0, 60) + " | " + el.textContent.trim().slice(0, 40),
            b: (nx.className || "").toString().slice(0, 60) + " | " + nx.textContent.trim().slice(0, 40),
          });
      }
      return bad;
    }, MIN);
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href);
    await wait(400);
    await ev(() => FOCA.api.demo_reset());
    await wait(150);
    await ev(() => FOCA.api.terms_accept("1"));
    await ev(() => FOCA.api.project_open("contoso"));
    await wait(300);
    for (const r of routes) {
      await ev(r => FOCA.reset([r]), r);
      await wait(350);
      const bad = await tight();
      ok(`${r}: stacked blocks keep >= ${MIN} px`, bad.length === 0, bad.slice(0, 3));
    }
    // Document card states: pick one document per status from the demo data.
    const ids = await ev(() => {
      const by = {};
      for (const d of FOCA.db.docs || []) if (!by[d.status_code]) by[d.status_code] = d.id;
      return by;
    });
    for (const st of ["queued", "downloaded", "analyzed", "error"]) {
      if (ids[st] == null) {
        log.push(["OK", `doc card ${st}: no such document in the demo, skipped`]);
        continue;
      }
      await ev(id => FOCA.reset(["/p/data/docs", `/p/doc/${id}`]), ids[st]);
      await wait(400);
      const bad = await tight();
      ok(`doc card (${st}): stacked blocks keep >= ${MIN} px`, bad.length === 0, bad.slice(0, 3));
      if (st === "downloaded") await page.screenshot({ path: `${out}/block-gaps_doc_${st}_${tag}.png` });
    }
    await ev(() => FOCA.reset(["/settings", "/settings/crawl"]));
    await wait(400);
    await ev(() => {
      const c = [...document.querySelectorAll(".page .card.nfs")].pop();
      if (c) c.scrollIntoView({ block: "center" });
    });
    await wait(200);
    await page.screenshot({ path: `${out}/block-gaps_crawl_${tag}.png` });
  } catch (e) {
    fails++;
    log.push(["FAIL", "exception", String((e && e.stack) || e).slice(0, 500)]);
  }
  fs.writeFileSync(`${out}/block-gaps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(
    log
      .map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] ?? "").slice(0, 400) : ""}`)
      .join("\n"),
  );
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
