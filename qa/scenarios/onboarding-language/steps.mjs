// Demo: first-run slides footer and the interface language picker.
// Welcome: "Skip · dots · Next" fits the viewport (Next fully inside, safe-area insets respected) at 360/393/412 px,
// font scale 1 and 2, in uk/en/ru. Appearance: the highlighted language segment matches the active setting for
// auto/uk/en/ru, also when settings.ui.look.lang holds an older value; the hint names the language in a
// grammatical form per UI language; the four options sit in a 2x2 grid.
// qa/shoot.sh --routes none --out $PWD/qa/out/onboarding-language --steps $PWD/qa/scenarios/onboarding-language/steps.mjs
import fs from "fs";
export default async (page, { out }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const shot = name => page.screenshot({ path: `${out}/${name}.png` }).catch(() => {});
  const setFs = f => ev(f => document.documentElement.style.setProperty("--fs", f), f);
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await wait(150);
    // Gesture bar and a side cutout, as on phones in landscape or with a display cutout.
    await ev(() => window.__setInsets(32, 24, 0, 12));

    // ---- Welcome footer ----
    // Wide OEM fonts (MiSans on HyperOS) render labels wider than the test font: widen the letters.
    await ev(() => { const s = document.createElement("style"); s.id = "qa-wide"; s.textContent = ".v2w-foot .btn { letter-spacing: 0.08em; }"; document.head.appendChild(s); });
    for (const lang of ["uk", "en", "ru"]) {
      await ev(l => FOCA.i18n.setLang(l), lang); await wait(300);
      for (const w of [360, 393, 412]) {
        for (const f of [1, 2]) {
          await page.setViewportSize({ width: w, height: 852 }); await setFs(f);
          await ev(() => FOCA.reset(["/welcome"])); await wait(450);
          const m = await ev(() => {
            const r = s => { const e = document.querySelector(s); if (!e || e.hidden) return null; const b = e.getBoundingClientRect(); return { l: b.left, r: b.right, t: b.top, b: b.bottom, sw: e.scrollWidth, cw: e.clientWidth }; };
            const insR = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--native-right")) || 0;
            return { vw: innerWidth, insR, next: r(".v2w-next"), skip: r('.v2w-foot [data-act="v2w-go:2"]'), dots: r(".v2w-dots"), foot: r(".v2w-foot"), docw: document.documentElement.scrollWidth };
          });
          const n = m.next, s = m.skip, d = m.dots;
          const inside = n && n.l >= 0 && n.r <= m.vw - m.insR + 0.5;
          const noOverlap = n && s && d && !(d.r > n.l + 0.5 && d.b > n.t + 0.5 && d.t < n.b - 0.5) && !(s.r > d.l + 0.5 && s.b > d.t + 0.5 && s.t < d.b - 0.5) && !(s.r > n.l + 0.5 && s.b > n.t + 0.5 && s.t < n.b - 0.5);
          const textFits = n && n.sw <= n.cw + 1 && s && s.sw <= s.cw + 1;
          ok(`welcome ${lang} ${w} fs${f}: Next fully inside the viewport`, inside, m);
          ok(`welcome ${lang} ${w} fs${f}: Skip, dots and Next do not overlap, labels fit`, noOverlap && textFits && m.docw <= m.vw, m);
          if (f === 1 && (w === 393 || w === 360)) await shot(`welcome_${lang}_${w}_fs1`);
          if (f === 2 && w === 360) await shot(`welcome_${lang}_${w}_fs2`);
        }
      }
    }
    await page.setViewportSize({ width: 393, height: 852 }); await setFs(1);
    await ev(() => document.getElementById("qa-wide").remove());

    // ---- Language picker ----
    // First run on a Ukrainian phone, no language ever chosen: UI is Ukrainian and "System (…)" is selected.
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1"));
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href, { waitUntil: "load" }); await wait(700);
    await ev(() => { window.__setInsets(32, 24, 0, 0); FOCA.state.deviceLocale = "uk-UA"; return FOCA.i18n.load("auto"); }); await wait(400);
    const saved0 = await ev(() => FOCA.api.settings_get ? FOCA.api.settings_get() : null).catch(() => null);
    ok("fresh install: no saved language choice", !saved0 || !saved0.lang || saved0.lang === "auto", saved0 && saved0.lang);
    await ev(() => FOCA.reset(["/settings", "/settings/appearance"])); await wait(450);
    const segOn = () => ev(() => { const b = document.querySelector(".st-lang [role=radio].on"); return { act: b && b.getAttribute("data-act"), label: b && b.textContent.trim(), ui: FOCA.i18n.lang(), title: document.querySelector(".st-lang") && document.querySelector(".st-lang").closest(".page").textContent.includes("Мова інтерфейсу") }; });
    let s0 = await segOn();
    ok("uk phone, no choice: UI is Ukrainian", s0.ui === "uk" && s0.title, s0);
    ok("uk phone, no choice: 'Як у системі (українська)' is selected", s0.act === "st-set:look.lang:AUTO" && /Як у системі \(українська\)/.test(s0.label || ""), s0);
    await shot("lang_first_run_uk_393");
    await page.click('.st-lang [data-act="st-set:look.lang:EN"]'); await wait(700);
    s0 = await segOn();
    ok("tap English: UI English, English highlighted", s0.ui === "en" && s0.act === "st-set:look.lang:EN", s0);
    await page.click('.st-lang [data-act="st-set:look.lang:AUTO"]'); await wait(700);
    s0 = await segOn();
    ok("tap System again: follows the phone (Ukrainian), System highlighted", s0.ui === "uk" && s0.act === "st-set:look.lang:AUTO", s0);

    const pick = () => ev(() => {
      const on = document.querySelector('.st-lang [role="radio"].on, .st-lang [aria-checked="true"]');
      const hint = document.querySelector(".st-lang + .fhint");
      const btns = [...document.querySelectorAll(".st-lang [role=radio]")].map(b => b.getBoundingClientRect());
      return { on: on ? on.getAttribute("data-act") : null, hint: hint ? hint.textContent.replace(/\s+/g, " ").trim() : "", rows: [...new Set(btns.map(b => Math.round(b.top)))].length, cols: [...new Set(btns.map(b => Math.round(b.left)))].length, ui: FOCA.i18n.lang(), setting: FOCA.i18n.setting() };
    });
    const WANT = { auto: "AUTO", uk: "UA", en: "EN", ru: "RU" };
    // Hint per UI language and active language: the language name in the right grammatical form.
    const HINT = {
      uk: { uk: /українську мову/, en: /англійську мову/, ru: /російську мову/ },
      ru: { uk: /украинский язык/, en: /английский язык/, ru: /русский язык/ },
      en: { uk: /Ukrainian/, en: /English/, ru: /Russian/ },
    };
    for (const setting of ["auto", "uk", "en", "ru"]) {
      for (const locale of setting === "auto" ? ["uk", "en", "ru"] : [null]) {
        if (locale) await ev(l => { FOCA.state.deviceLocale = l; }, locale);
        await ev(s => FOCA.i18n.setLang(s), setting); await wait(300);
        await ev(() => FOCA.reset(["/settings", "/settings/appearance"])); await wait(450);
        const r = await pick();
        const tag = `lang setting=${setting}${locale ? " device=" + locale : ""}`;
        ok(`${tag}: highlighted segment matches the setting`, r.on === `st-set:look.lang:${WANT[setting]}`, r);
        const ui = r.ui;
        ok(`${tag}: hint names ${ui} in the right form`, HINT[ui][ui].test(r.hint) && !/використовують Українська|используют Русский/.test(r.hint), r.hint);
        ok(`${tag}: options form a 2x2 grid`, r.rows === 2 && r.cols === 2, r);
        if (setting === "auto" && locale === "uk") await shot("lang_auto_uk_393");
      }
    }
    // Hint in the UK interface for other active languages is impossible (UI follows the language), but the
    // keys are per language: check the dictionary forms directly.
    for (const ui of ["uk", "ru", "en"]) {
      await ev(l => FOCA.i18n.setLang(l), ui); await wait(250);
      for (const l of ["uk", "en", "ru"]) {
        const t = await ev(l => FOCA.t(`look.lang_in_${l}`, ""), l);
        ok(`dictionary ${ui}: look.lang_in_${l} has the right form`, HINT[ui][l].test(t), t);
      }
    }
    // Older builds stored settings.ui.look.lang next to the real setting: a stale "RU" must not win.
    await ev(() => FOCA.state.deviceLocale = "uk");
    await ev(() => FOCA.api.settings_set({ lang: "auto", ui: { look: { lang: "RU", theme: "dark" } } }));
    await page.goto(new URL("../../../ui/index.html#/settings/appearance", import.meta.url).href, { waitUntil: "load" }); await wait(800);
    await ev(() => window.__setInsets(32, 24, 0, 0));
    await ev(() => { FOCA.state.deviceLocale = "uk"; return FOCA.i18n.load("auto"); }); await wait(400);
    await ev(() => FOCA.reset(["/settings", "/settings/appearance"])); await wait(450);
    const stale = await pick();
    ok("stale ui.look.lang=RU with setting auto: Auto is highlighted", stale.on === "st-set:look.lang:AUTO", stale);
    await shot("lang_stale_uk_393");
    await ev(() => FOCA.i18n.setLang("ru"));
  } catch (e) { fails++; log.push(["FAIL", "exception", String((e && e.stack) || e).slice(0, 500)]); }
  fs.writeFileSync(`${out}/onboarding_language_steps.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] ?? "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
