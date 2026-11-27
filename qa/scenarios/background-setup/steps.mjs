// Demo: OEM background helper and "Hide from Recents during scans".
// Settings › Background is one screen: the firmware steps show the state the platform reports (autostart and
// battery: on / off / unknown, re-read when the app returns from system settings) and count it in "done N of M";
// manual "Done" only for steps the system does not report (pin in Recents while hiding is off), persisted.
// There is no "background pop-ups" step: the app never starts an activity from the background, and HyperOS
// has no permission under the old name.
// Each "Open" passes the screen name the native layer maps to the right Xiaomi page. The hide-from-Recents
// toggle (default on for this OEM, stored by the native layer through platform_bg_set) lives here too. The launch
// screen repeats the autostart/battery card while something is still missing; Debug › Device lists the autostart
// state. EN and UK texts are checked as well.
// qa/shoot.sh --routes none --out $PWD/qa/out/background-setup --steps $PWD/qa/scenarios/background-setup/steps.mjs
import fs from "fs";
export default async (page, { out }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const text = sel => ev(s => { const e = document.querySelector(s); return e ? e.textContent.replace(/\s+/g, " ").trim() : null; }, sel);
  const shot = name => page.screenshot({ path: `${out}/bg_${name}.png` }).catch(() => {});
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    await ev(() => FOCA.i18n && FOCA.i18n.setLang("ru")); await wait(200);

    const st0 = await ev(() => FOCA.api.platform_bg_status());
    ok("bg status has the fixed shape", ["oem", "autostart", "battery_unrestricted", "hide_recents", "hide_recents_default"].every(k => k in st0), st0);
    ok("demo device defaults: Xiaomi, autostart off, hiding on", st0.oem === "xiaomi" && st0.autostart === "off" && st0.hide_recents === true, st0);

    await ev(() => FOCA.reset(["/projects", "/settings", "/settings/battery"])); await wait(600);
    // One screen: the firmware steps carry the detected state; no separate autostart/battery card here.
    ok("Settings › Background has no duplicate OEM card", !(await ev(() => document.querySelector('.bg-setup[data-where="settings"]'))));
    const steps = () => ev(() => [...document.querySelectorAll(".st-howto .st-hs")].map(li => ({
      state: li.dataset.state, done: li.classList.contains("done"),
      manual: !!li.querySelector('[data-act^="st-bdone:"]'),
      open: (li.querySelector('[data-act^="st-android:"]') || {}).dataset?.act || null,
      pill: (li.querySelector(".st-hst") || {}).textContent?.trim() || "",
    })));
    const head = () => ev(() => { const h = [...document.querySelectorAll(".page h3, .page .sec-h")].find(e => /Прошивка|Прошивка|Firmware/.test(e.textContent)); return h ? h.textContent.replace(/\s+/g, " ").trim() : ""; });
    const refreshOnResume = async () => { await ev(() => document.dispatchEvent(new Event("visibilitychange"))); await wait(500); };
    let s = await steps();
    ok("Xiaomi: four steps, no background pop-ups step", s.length === 4, s);
    ok("no step names MIUI Other permissions or pop-ups", !/Другие разрешения|всплывающие/i.test((await text(".st-howto")) || ""), await text(".st-howto"));
    ok("autostart and battery steps show the detected state (off), no manual Done", s[0].state === "off" && s[1].state === "off" && !s[0].manual && !s[1].manual && /Выключено/.test(s[1].pill), s);
    ok("hiding from Recents is on: the pin-in-Recents step reads 'not needed' (alternatives)", s[2].state === "na" && !s[2].manual && s[2].done && /Не нужно/.test(s[2].pill), s);
    ok("Open buttons: autostart list, battery saver; none for the Recents step",
      s[0].open === "st-android:Приложения" && s[1].open === "st-android:Контроль активности" && !s[2].open, s);
    ok("lock screen step: detected on, opens the channel settings, says there is no permission", s[3].state === "on" && !s[3].manual && s[3].open === "st-android:Экран блокировки" && /разрешения для этого нет/.test((await text('.st-howto .st-hs[data-step="3"]')) || ""), s[3]);
    ok("header counts 2 of 4 (not-needed and lock screen)", /выполнено 2 из 4/.test(await head()), await head());
    await ev(() => FOCA.api.platform_bg_set({ demo_lockscreen: "off" }));
    await refreshOnResume();
    s = await steps();
    ok("lock screen hidden: the step reads off", s[3].state === "off" && /Выключено/.test(s[3].pill), s[3]);
    await ev(() => FOCA.api.platform_bg_set({ demo_lockscreen: "on" }));
    await refreshOnResume();
    const ov = await ev(() => { const c = document.querySelector(".st-howto"); return c ? c.scrollWidth - c.clientWidth : -1; });
    ok("steps do not overflow horizontally", ov === 0, ov);
    const chips = await ev(() => [...document.querySelectorAll(".st-chips .chip")].map(c => Math.round(c.getBoundingClientRect().top)));
    ok("firmware chips wrap inline (first two on one row)", chips.length === 3 && chips[0] === chips[1], chips);
    // Narrow phone with a wide OEM font: still at most two rows, Xiaomi and Samsung side by side.
    await page.setViewportSize({ width: 360, height: 852 });
    await ev(() => { const s = document.createElement("style"); s.id = "qa-wide"; s.textContent = ".st-chips .chip { letter-spacing: 0.05em; }"; document.head.appendChild(s); }); await wait(200);
    const chips360 = await ev(() => [...document.querySelectorAll(".st-chips .chip")].map(c => Math.round(c.getBoundingClientRect().top)));
    ok("360 px, wide font: chips share rows (Xiaomi and Samsung on one row, two rows at most)", chips360[0] === chips360[1] && new Set(chips360).size <= 2, chips360);
    await shot("chips_360");
    await ev(() => document.getElementById("qa-wide").remove()); await page.setViewportSize({ width: 393, height: 852 }); await wait(200);

    // The phone reports autostart on and battery unrestricted (as on the owner's Xiaomi): all done after resume.
    await ev(() => FOCA.api.platform_bg_set({ demo_autostart: "on", demo_battery: true }));
    await refreshOnResume();
    s = await steps();
    ok("after resume: autostart and battery read on", s[0].state === "on" && s[1].state === "on" && s[0].done && s[1].done && /Включено/.test(s[0].pill), s);
    ok("header counts 4 of 4 with no manual step left", /выполнено 4 из 4/.test(await head()) && !s.some(x => x.manual), await head());
    await shot("steps_ru");
    // Unknown state: Done by hand becomes available for that step.
    await ev(() => FOCA.api.platform_bg_set({ demo_autostart: "unknown", demo_battery: "unknown" }));
    await refreshOnResume();
    s = await steps();
    ok("unknown state: '? Не удалось определить' with a manual Done", s[0].state === "unknown" && s[0].manual && /Не удалось определить/.test(s[0].pill) && s[1].state === "unknown", s);
    ok("unknown steps are not counted unless marked: 2 of 4", /выполнено 2 из 4/.test(await head()), await head());
    // Manual marks survive a reload.
    await page.click('[data-act="st-bdone:0"]'); await wait(300);
    await page.goto("about:blank"); await page.goto(new URL("../../../ui/index.html#/settings/battery", import.meta.url).href); await wait(1200);
    ok("manual mark persisted across reload: 3 of 4", /выполнено 3 из 4/.test(await head()), await head());
    await page.click('[data-act="st-bdone:0"]'); await wait(300);
    // Back to the demo device defaults (battery follows the Settings flag again) for the launch checks.
    await ev(() => FOCA.api.platform_bg_set({ demo_autostart: "off", demo_battery: null }));
    await refreshOnResume();

    // Hide-from-Recents toggle: on by default here, a tap stores off through the native command.
    const tgSel = '[data-act="st-hide-recents"].toggle';
    ok("hide-from-Recents toggle is on", await ev(s => { const t = document.querySelector(s); return !!t && t.classList.contains("on"); }, tgSel));
    ok("toggle explains the way back", /уведомление скана/.test((await text('.st-tr[data-act="st-hide-recents"]')) || ""));
    await shot("settings_ru");
    await page.click('.st-tr[data-act="st-hide-recents"] .body'); await wait(500);
    let st = await ev(() => FOCA.api.platform_bg_status());
    ok("tap turns hiding off (stored)", st.hide_recents === false && st.hide_recents_chosen === true, st);
    ok("toggle renders off", await ev(s => { const t = document.querySelector(s); return !!t && !t.classList.contains("on"); }, tgSel));
    await wait(300);
    const sOff = await steps();
    ok("hiding off: pin-in-Recents becomes a manual step again", sOff[2].state === "manual" && sOff[2].manual, sOff[2]);
    await page.click(tgSel); await wait(500);
    st = await ev(() => FOCA.api.platform_bg_status());
    ok("second tap turns it back on", st.hide_recents === true, st);

    // Launch screen: the card is repeated while autostart or battery is still missing.
    await ev(() => FOCA.go("/new")); await wait(700);
    ok("launch screen shows the background hint", !!(await text('#la-bg .bg-setup[data-where="launch"]')), await text("#la-bg"));
    ok("launch hint has its title", /Чтобы прошивка не остановила скан/.test((await text("#la-bg")) || ""));
    await shot("launch_ru");

    // Enable autostart (demo pretends the system screen was used) → pill instead of the button.
    await page.click('#la-bg [data-act="st-bg-auto"]'); await wait(600);
    ok("autostart reads on after the system screen", (await ev(() => FOCA.api.platform_bg_status())).autostart === "on");
    // Battery: demo marks the app excluded after a short delay; the hint disappears when nothing is missing.
    await page.click('#la-bg [data-act="st-bg-batt"]'); await wait(2600);
    ok("launch hint is gone once autostart and battery are set", (await text("#la-bg")) === "", await text("#la-bg"));

    // Debug › Device: the autostart line of device.txt.
    await ev(() => FOCA.go("/settings/debug/dev")); await wait(900);
    const dev = await ev(() => document.body.textContent.replace(/\s+/g, " "));
    ok("Debug › Device lists autostart", /autostart\s*on/.test(dev), dev.slice(dev.indexOf("autostart") - 20, dev.indexOf("autostart") + 30));

    // EN / UK texts of the card and the toggle.
    await ev(() => FOCA.api.platform_bg_set({ hide_recents: true }));
    await ev(() => FOCA.api.platform_bg_set({ demo_autostart: "on", demo_battery: true }));
    for (const [lang, re] of [["en", /Hide from Recents during scans[\s\S]*4 of 4 done[\s\S]*Autostart\s*On/], ["uk", /Приховувати з «Нещодавніх» під час скану[\s\S]*виконано 4 з 4[\s\S]*Автозапуск\s*Увімкнено/]]) {
      await ev(l => FOCA.i18n.setLang(l), lang); await wait(400);
      await ev(() => FOCA.go("/settings/battery")); await wait(700);
      const t = await ev(() => FOCA.page().textContent.replace(/\s+/g, " "));
      ok(`${lang}: steps and toggle are translated`, re.test(t), t.slice(0, 300));
      await shot(`settings_${lang}`);
    }
    await ev(() => FOCA.i18n.setLang("ru"));
  } catch (e) { fails++; log.push(["FAIL", "exception", String((e && e.stack) || e).slice(0, 500)]); }
  fs.writeFileSync(`${out}/background_setup_steps.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] ?? "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
