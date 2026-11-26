// Demo: phone layout fixes, no page zoom, wordlist fuzz parameters at narrow widths, PIN keypad without letters.
// qa/shoot.sh --routes none --out $PWD/qa/out/layout-rc2 --w 393 --fs 2 --steps $PWD/qa/scenarios/layout-rc2/steps.mjs
export default async (page, { out, W, fsc, theme, go }) => {
  let fails = 0, oks = 0;
  const ok = (name, cond, data) => {
    if (cond) oks++; else fails++;
    console.log(`${cond ? "OK  " : "FAIL"} ${name}${cond ? "" : " " + JSON.stringify(data).slice(0, 400)}`);
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const tag = `${W}_fs${fsc}_${theme}`;
  const shot = async n => { await wait(250); await page.screenshot({ path: `${out}/layout_rc2_${n}_${tag}.png` }); };
  try {
    // Page zoom is off: viewport meta, touch-action on the root; the in-app font scale still works.
    await go("/settings/appearance");
    const z = await ev(() => {
      const m = document.querySelector('meta[name="viewport"]').content;
      const cs = getComputedStyle(document.documentElement);
      const fs0 = parseFloat(cs.fontSize);
      const prev = document.documentElement.style.getPropertyValue("--fs");
      document.documentElement.style.setProperty("--fs", "1.5");
      const fs1 = parseFloat(getComputedStyle(document.documentElement).fontSize);
      document.documentElement.style.setProperty("--fs", prev);
      return { m, ta: cs.touchAction, fs0, fs1 };
    });
    ok("viewport meta forbids page zoom", /maximum-scale=1\b/.test(z.m) && /user-scalable=no/.test(z.m) && /width=device-width/.test(z.m), z);
    ok("root touch-action is manipulation (no double-tap zoom)", z.ta === "manipulation", z);
    ok("in-app font scale (--fs) still scales the root font", Math.abs(z.fs1 - 21) < 0.5 && Math.abs(z.fs0 - 14 * fsc) < 0.5, z);

    // Wordlists → fuzz parameters in the longer languages: value and unit never overlap, ⓘ stays on the
    // label line, the stepper goes under the label on a narrow field, the cards keep a gap.
    for (const lang of ["uk", "en"]) {
      await ev(async l => { await FOCA.i18n.setLang(l); FOCA.go("/settings/wordlists"); }, lang);
      await wait(500);
      const r = await ev(() => {
        const R = e => e && e.getBoundingClientRect();
        const rows = [...document.querySelectorAll(".st-nfs .nf")].map(n => {
          const lab = n.querySelector(".nf-l label"), info = R(n.querySelector(".nf-l .hl-i")), inp = n.querySelector(".nf-in");
          const u = R(n.querySelector(".nf-u")), ir = R(inp), box = R(n.querySelector(".nf-box")), ctl = R(n.querySelector(".nf-ctl"));
          const top = R(n.querySelector(".nf-top")), rg = document.createRange();
          rg.selectNodeContents(lab);
          const lines = [...rg.getClientRects()], last = lines[lines.length - 1], lr = R(lab);
          const iy = info ? (info.top + info.bottom) / 2 : 0;
          return {
            id: n.dataset.nf,
            label: lab.textContent.trim(),
            fits: inp.scrollWidth <= inp.clientWidth + 1,
            unitApart: !u || u.left >= ir.right - 0.5,
            unitInBox: !u || (u.right <= box.right + 0.5 && u.left >= box.left - 0.5),
            infoInline: !info || (iy >= last.top - 6 && iy <= last.bottom + 6 && info.left >= last.right - 1),
            ctlInside: ctl.left >= top.left - 0.5 && ctl.right <= top.right + 0.5,
            stacked: ctl.top >= lr.bottom - 0.5,
            narrow: n.clientWidth - 28 < 26 * parseFloat(getComputedStyle(document.documentElement).fontSize),
          };
        });
        const card = R(document.querySelector(".st-nfs")), next = R(document.querySelector(".st-nfs + .list"));
        return { rows, gap: next ? Math.round(next.top - card.bottom) : null };
      });
      const bad = k => r.rows.filter(x => !x[k]).map(x => x.label);
      ok(`wordlists [${lang}]: four parameter fields rendered`, r.rows.length === 4, r);
      ok(`wordlists [${lang}]: values fit their fields`, !bad("fits").length, bad("fits"));
      ok(`wordlists [${lang}]: unit sits next to the value, never on top of it`, !bad("unitApart").length && !bad("unitInBox").length, r.rows);
      ok(`wordlists [${lang}]: ⓘ stays on the label line`, !bad("infoInline").length, bad("infoInline"));
      ok(`wordlists [${lang}]: stepper inside the row`, !bad("ctlInside").length, bad("ctlInside"));
      ok(`wordlists [${lang}]: narrow field puts the stepper under the label`, r.rows.every(x => !x.narrow || x.stacked), r.rows);
      ok(`wordlists [${lang}]: gap between the parameters card and the option list`, r.gap >= 12, r.gap);
      if (lang === "uk") {
        await ev(() => document.querySelector(".st-nfs").scrollIntoView());
        await shot("wordlists_uk");
      }
    }
    await ev(async () => { await FOCA.i18n.setLang("ru"); });

    // PIN keypad: digits only, no phone-dialer letters under them.
    for (const lang of ["uk", "en"]) {
      await ev(async l => { await FOCA.i18n.setLang(l); FOCA.go("/lock"); }, lang);
      await wait(400);
      const k = await ev(() => [...document.querySelectorAll('.st-pad-keys [data-act^="st-lk:"]')].map(b => {
        const r = b.getBoundingClientRect(), d = b.querySelector("b").getBoundingClientRect();
        return { t: b.textContent.trim(), small: !!b.querySelector("small"), w: Math.round(r.width), h: Math.round(r.height), dy: Math.round((d.top + d.bottom) / 2 - (r.top + r.bottom) / 2) };
      }));
      ok(`/lock [${lang}]: ten digit keys`, k.length === 10, k);
      ok(`/lock [${lang}]: keys show only the digit`, k.every(x => /^\d$/.test(x.t) && !x.small), k.filter(x => !/^\d$/.test(x.t) || x.small));
      ok(`/lock [${lang}]: digits centred in round keys of at least 44 px`, k.every(x => x.w >= 44 && x.h >= 44 && Math.abs(x.dy) <= 2), k);
      if (lang === "uk") await shot("lock_uk");
    }
    // Leave the lock screen with the demo PIN.
    for (const d of "1234") await ev(x => FOCA.actions["st-lk"](x), d);
    await ev(async () => { await FOCA.i18n.setLang("ru"); });
  } catch (e) {
    ok("scenario ran without exceptions", false, String(e && e.stack || e));
  }
  console.log(`${oks} OK, ${fails} FAIL`);
};
