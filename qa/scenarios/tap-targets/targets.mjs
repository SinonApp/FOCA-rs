// Audit of tap targets ≥ 44×44 on every route.
// The target size is the real hit area: the element box or, if it is under 44 px along an axis,
// an elementFromPoint check at center ± 21.5 px along that axis (this accounts for ::after with a negative inset).
// Exceptions: text links inside a paragraph (WCAG 2.5.8 inline), hidden or covered elements (the center misses the element).
// qa/shoot.sh --routes /p/overview --out qa/scenarios/tap-targets --w 393 --fs 1.3 --steps $PWD/qa/scenarios/tap-targets/targets.mjs
import fs from "fs";
export default async (page, { out, W, prep }) => {
  const routes = fs.readFileSync(new URL("../../routes.txt", import.meta.url), "utf8").split(/\s+/).filter(Boolean).concat(["/p/preflight", "/welcome"]);
  const uniq = [...new Set(routes)];
  const fsc = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--fs").trim() || "1");
  const small = [];
  for (const r of uniq) {
    await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(350);
    const res = await page.evaluate(() => {
      const SEL = "button, [data-act], [role=button], [role=tab], [role=radio], [role=checkbox], [role=switch], a[href], input:not([type=hidden]), select, textarea, [data-tab], [data-hold]";
      const out = [];
      const els = [...document.querySelectorAll(SEL)].filter(el => !el.closest(".page") || el.closest(".page") === (FOCA.page && FOCA.page()));
      for (const el of els) {
        if (el.parentElement && el.parentElement.closest(SEL) && !el.matches("button, a[href], input, select, textarea, [data-hold]")) continue; // nested part of a clickable row
        const cs = getComputedStyle(el); if (cs.display === "none" || cs.visibility === "hidden" || el.closest("[hidden]")) continue;
        if (el.matches("a[href]") && el.closest("p, li") && !el.matches(".pill, .btn, .chip")) continue;
        if (el.matches("input[type=checkbox], input[type=radio]") && el.closest("label")) continue; // the hit area is the label
        let q = el.getBoundingClientRect(); if (!q.width || !q.height) continue;
        if (q.width >= 44 && q.height >= 44) continue;
        el.scrollIntoView({ block: "center", inline: "center" }); q = el.getBoundingClientRect();
        const cx = q.left + q.width / 2, cy = q.top + q.height / 2;
        const hit = (x, y) => { if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return false; const e = document.elementFromPoint(x, y); return !!(e && (e === el || el.contains(e))); };
        if (!hit(cx, cy)) continue; // covered by a sticky panel or sheet: skip
        const okW = q.width >= 44 || (hit(cx - 21.5, cy) && hit(cx + 21.5, cy));
        const okH = q.height >= 44 || (hit(cx, cy - 21.5) && hit(cx, cy + 21.5));
        if (okW && okH) continue;
        const name = (el.getAttribute("aria-label") || el.textContent || el.getAttribute("placeholder") || "").trim().replace(/\s+/g, " ").slice(0, 40);
        out.push({ w: Math.round(q.width), h: Math.round(q.height), okW, okH, tag: el.tagName.toLowerCase(), cls: (el.className && el.className.baseVal == null ? el.className : "").toString().slice(0, 40), act: el.dataset.act || el.dataset.hold || el.dataset.tab || el.id || "", name });
      }
      return out;
    });
    res.forEach(x => small.push({ route: r, ...x }));
  }
  // "All time" timeline (10 years for contoso): bars are at least 44 px wide and the page is not wider than the screen.
  await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#/p/timeline", import.meta.url).href); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300);
  await page.evaluate(() => FOCA.actions["v2t-per"]("all")); await page.waitForTimeout(300);
  const tl = await page.evaluate(() => { const bs = [...document.querySelectorAll(".v2t-bar")]; const c = document.querySelector(".v2t-bars"); return { n: bs.length, minW: Math.min(...bs.map(b => b.getBoundingClientRect().width)), docw: document.documentElement.scrollWidth > innerWidth, atEnd: c.scrollLeft + c.clientWidth >= c.scrollWidth - 2 }; });
  if (!(tl.n >= 2 && tl.minW >= 44 && !tl.docw && tl.atEnd)) small.push({ route: "/p/timeline (all time)", w: Math.round(tl.minW), h: 0, okW: false, okH: true, tag: "button", cls: "v2t-bar", act: "v2t-year", name: JSON.stringify(tl) });
  // Group by class/action without the argument.
  const key = x => `${x.tag}.${x.cls.split(" ")[0]}[${(x.act || "").split(":")[0]}] ${x.w}x${x.h}`;
  const groups = {}; small.forEach(x => { const k = key(x); (groups[k] = groups[k] || { n: 0, routes: new Set(), ex: x.name }).n++; groups[k].routes.add(x.route); });
  const summary = Object.entries(groups).map(([k, g]) => `${k} ×${g.n} ${[...g.routes].slice(0, 4).join(",")} «${g.ex}»`);
  fs.writeFileSync(`${out}/targets_${W}_fs${fsc}.json`, JSON.stringify({ n: small.length, summary, small }, null, 1));
  console.error(summary.join("\n"));
  console.error(`tap-targets ${W}/fs${fsc}: ${small.length === 0 ? "1 OK, 0 FAIL" : "0 OK, 1 FAIL"} (small targets: ${small.length})`);
  if (small.length) console.error("FAIL tap targets < 44 px");
};
