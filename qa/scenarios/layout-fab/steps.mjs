// Demo: first-run buttons are not clipped; the new scan FAB does not cover the snackbar or the last list rows.
// qa/shoot.sh --routes none --out $PWD/qa/scenarios/layout-fab --w 393 --fs 2 --theme dark --steps $PWD/qa/scenarios/layout-fab/steps.mjs
import fs from "fs";
export default async (page, { out, prep, W, fsc, theme, checkText }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); console.log(`${cond ? "OK  " : "FAIL"} ${name}${cond ? "" : " " + JSON.stringify(data).slice(0, 400)}`); };
  const go = async r => { await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r); await page.waitForTimeout(250); await prep(); await page.waitForTimeout(300); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const tag = `${W}_fs${fsc}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/layout_fab_${n}_${tag}.png` }); };
  // Every footer button fits the window and stays clear of the system navigation (--native-bottom).
  const footFits = () => ev(() => {
    const vw = document.documentElement.clientWidth, vh = innerHeight;
    const nb = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--native-bottom")) || 0;
    const bs = [...document.querySelectorAll(".page .ob-foot .btn")].filter(b => b.offsetParent);
    const bad = bs.map(b => { const r = b.getBoundingClientRect(), rg = document.createRange(); rg.selectNodeContents(b); const tr = rg.getBoundingClientRect();
        // Text margin to the button edge (≥ 8 px): a tight fit gets clipped on a phone with a wider font.
        return { t: b.textContent.trim(), l: Math.round(r.left), r: Math.round(r.right), b: Math.round(r.bottom), sw: b.scrollWidth, cw: b.clientWidth, gapL: Math.round(tr.left - r.left), gapR: Math.round(r.right - tr.right) }; })
      .filter(x => x.l < 0 || x.r > vw + 0.5 || x.b > vh - nb + 0.5 || x.sw > x.cw + 1 || x.gapR < 8 || x.gapL < 8);
    return { n: bs.length, bad, vw, vh, nb };
  });
  const bottom = () => ev(() => { const s = document.querySelector(".page"); if (s) s.scrollTop = s.scrollHeight; window.scrollTo(0, document.body.scrollHeight); });
  try {
    // wide: an OEM font wider than Inter/Roboto (MiSans on HyperOS), simulated with letter-spacing.
    // tz: Android WebView textZoom (system font size 130%) enlarges text but not the rem-based layout widths.
    for (const [nb, wide] of [[0, false], [48, false], [48, true], [48, "tz"]]) {
      const tg = `nav ${nb}px${wide === "tz" ? ", textZoom 130" : wide ? ", wide font" : ""}`;
      await go("/terms");
      await ev(n => document.documentElement.style.setProperty("--native-bottom", n + "px"), nb);
      if (wide) await ev(w => { const st = document.createElement("style"); st.textContent = w === "tz" ? ".ob-foot .btn { font-size: calc(.95 * 14px * 1.3) !important; letter-spacing: .06em !important; }" : "body, .btn { letter-spacing: .09em !important; }"; document.head.appendChild(st); }, wide);
      await ev(() => FOCA.go("/terms")); await wait(300); await bottom(); await wait(200);
      let f = await footFits();
      ok(`/terms (${tg}): "Не принимаю"/"Принимаю и продолжаю" fully visible`, f.n >= 2 && !f.bad.length, f);
      // All checkboxes ticked and the text read: the enabled button also fits.
      await ev(() => { document.querySelectorAll('[data-act^="ob-check:"]').forEach(e => { if (!e.classList.contains("on") && !e.querySelector(".on, :checked")) e.click(); }); });
      await wait(250); await bottom(); await wait(250);
      f = await footFits();
      const en = await ev(() => { const b = document.getElementById("ob-accept"); return b ? !b.disabled : null; });
      ok(`/terms (${tg}): enabled "Принимаю и продолжаю" fully visible`, f.n >= 2 && !f.bad.length, { f, en });
      if (nb && !wide) await shot("terms"); if (wide) await shot(wide === "tz" ? "terms_tz" : "terms_wide");
      await ev(() => FOCA.go("/permissions")); await wait(400); await bottom(); await wait(200);
      f = await footFits();
      ok(`/permissions (${tg}): "Позже"/"Разрешить всё" (or a single "Далее") fully visible`, f.n >= 1 && !f.bad.length, f);
      if (nb && !wide) await shot("perms");
    }
    // /welcome (intro: slides, consent checkbox, "next" at the bottom right).
    for (const nb of [0, 48]) {
      await go("/welcome");
      await ev(n => document.documentElement.style.setProperty("--native-bottom", n + "px"), nb);
      for (const i of [0, 1, 2]) {
        await ev(k => FOCA.actions["v2w-go"](String(k)), i); await wait(450);
        if (i === 2) { await ev(() => { const c = document.querySelector('[data-act="v2w-ok"]'); if (c) c.click(); }); await wait(300); }
        await ev(() => document.querySelectorAll(".v2w-sl").forEach(x => { x.scrollTop = x.scrollHeight; })); await wait(200);
        const f = await ev(() => {
          const vw = document.documentElement.clientWidth, vh = innerHeight;
          const nbp = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--native-bottom")) || 0;
          const sl = document.querySelectorAll(".v2w-sl")[FOCA.state.v2w ? 0 : 0];
          const bs = [...document.querySelectorAll(".v2w-foot .btn, .v2w-sl:not([aria-hidden]) .btn")].filter(b => b.offsetParent && !b.hidden);
          const bad = bs.map(b => { const r = b.getBoundingClientRect(); return { t: b.textContent.trim(), l: Math.round(r.left), r: Math.round(r.right), b: Math.round(r.bottom), sw: b.scrollWidth, cw: b.clientWidth }; })
            .filter(x => x.l < 0 || x.r > vw + 0.5 || x.b > vh - nbp + 0.5 || x.sw > x.cw + 1);
          return { n: bs.length, bad, vw, vh, nbp };
        });
        ok(`/welcome slide ${i + 1} (nav ${nb}px): buttons fully visible`, f.n >= 1 && !f.bad.length, f);
        if (nb && i !== 1) await shot(`welcome${i + 1}`);
      }
    }
    // Xiaomi lock hint on the permissions screen (the demo reports the OEM like a real phone; override it).
    await go("/permissions"); await wait(300);
    const t = await ev(() => { const st = FOCA.state.perms.st || {}; FOCA.state.perms.st = { ...st, oem: "xiaomi", manufacturer: "Xiaomi" }; FOCA.render(true); return (document.querySelector(".page") || document.body).innerText; });
    ok('Xiaomi permissions: "Закрепить в Недавних … замок"', /Недавних/.test(t) && /замок/.test(t), t.slice(0, 300));
    await checkText("layout-fab /permissions");

    // FAB and snackbar.
    await go("/projects"); await ev(() => FOCA.api.demo_reset()); await wait(200);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(200);
    for (const r of ["/projects", "/p/overview", "/p/findings", "/p/data/docs"]) {
      await ev(x => FOCA.go(x), r); await wait(400);
      const fab = await ev(() => { const f = document.querySelector(".fab"); return f && f.offsetParent ? f.getBoundingClientRect().toJSON() : null; });
      if (!fab) continue;
      await ev(() => FOCA.snack("Проверка: snackbar над кнопкой", { ms: 8000 })); await wait(350);
      const sn = await ev(() => { const s = document.querySelector("#snack, .snack"); return s ? s.getBoundingClientRect().toJSON() : null; });
      ok(`${r}: snackbar not covered by FAB`, sn && (sn.bottom <= fab.top + 1 || sn.right <= fab.left || sn.left >= fab.right), { sn, fab });
      // The last list row is visible above the FAB after scrolling to the end.
      await bottom(); await wait(250);
      const last = await ev(() => { const rows = [...document.querySelectorAll(".page .row, .page .card")].filter(e => e.offsetParent); const e = rows[rows.length - 1]; return e ? e.getBoundingClientRect().toJSON() : null; });
      ok(`${r}: last row not under FAB`, !last || last.bottom <= fab.top + 1 || last.right <= fab.left, { last, fab });
      if (r === "/p/overview") await shot("fab_snack");
    }
    // The FAB appears AFTER the snackbar is placed (scan finished: "scan finished" snackbar, then the new scan FAB).
    await ev(() => FOCA.go("/p/scan")); await wait(400);
    await ev(() => { document.getElementById("fab").classList.remove("show"); FOCA.placeSnack(); FOCA.snack("Скан завершён · новых находок нет", { ms: 8000 }); }); await wait(300);
    await ev(() => { const f = document.getElementById("fab"); f.classList.add("show"); f.classList.remove("small"); f.innerHTML = '<span class="fab-l">Новый скан</span>'; }); await wait(300);
    const late = await ev(() => { const f = document.getElementById("fab").getBoundingClientRect(), s = document.getElementById("snack").getBoundingClientRect(); return { f: f.toJSON(), s: s.toJSON() }; });
    ok("FAB shown after snackbar: snackbar still above FAB", late.s.bottom <= late.f.top + 1, late);
    await shot("fab_late");
  } catch (e) { ok("scenario without exceptions", false, String(e.stack || e)); }
  const nOk = log.filter(l => l[0] === "OK").length;
  console.log(`${nOk} OK, ${fails} FAIL`);
  fs.writeFileSync(`${out}/layout_fab_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
};
