// Reports steps: export sheets, history, report generation.
export default async (page, { out, W, prep }) => {
  const sfx = await page.evaluate(
    () =>
      `${innerWidth}_fs${getComputedStyle(document.documentElement).getPropertyValue("--fs").trim()}_${document.documentElement.dataset.theme}`,
  );
  const shot = async n => {
    await page.waitForTimeout(450);
    const ov = await page.evaluate(() =>
      [...document.querySelectorAll(".page, .sheet .sh-b")].map(e => e.scrollWidth - e.clientWidth),
    );
    console.error("STEP", n, "overflow", JSON.stringify(ov));
    await page.screenshot({ path: `${out}/step_${n}_${sfx}.png` });
  };
  const go = async r => {
    await page.goto("about:blank");
    await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r);
    await page.waitForTimeout(250);
    await prep();
    await page.waitForTimeout(300);
  };
  const only = (process.env.E_STEPS || "rp").split(",");
  if (only.includes("rp")) {
    await go("/p/reports");
    await page.evaluate(() => FOCA.exportSheet({ kind: "findings" }));
    await shot("ex1");
    await page.click('[data-act="rp-ex-fmt:csv"]');
    await shot("ex2_csv");
    await page.click('[data-act="rp-ex-secrets"]');
    await page.waitForTimeout(200);
    await page.evaluate(() => {
      const b = document.querySelector(".sheet .sh-b");
      b.scrollTop = b.scrollHeight;
    });
    await shot("ex3_secrets");
    await page.click('[data-act="rp-ex-share"]');
    await shot("ex4_share");
    await page.evaluate(() => FOCA.closeSheet());
    await page.evaluate(() => FOCA.actions["rp-quick"]("dict"));
    await shot("ex5_dict");
    await page.evaluate(() => FOCA.closeSheet());
    await page.evaluate(() => FOCA.actions["rp-hmenu"]("3"));
    await shot("hist_menu");
    await page.click('[data-act="rp-h-del:3"]');
    await shot("hist_deleted");
    await go("/p/report-new");
    await page.click('[data-act="rp-d:secrets:full"]');
    await page.waitForTimeout(200);
    await page.evaluate(() => {
      const p = document.querySelector(".page");
      p.scrollTop = p.scrollHeight;
    });
    await shot("new_bottom");
    await page.click('[data-act="rp-build"]');
    await page.waitForTimeout(300);
    // Full secrets ask for confirmation first.
    if (await page.$('[data-act="rp-build-full"]')) {
      await shot("build_full_secrets_warn");
      await page.click('[data-act="rp-build-full"]');
    }
    await page.waitForTimeout(900);
    await shot("build_progress");
    await page.waitForTimeout(2600);
    await shot("build_done");
    // For PDF the "open" action is "print → PDF"; open the preview as rp-b-open.
    if (await page.$('[data-act="rp-b-print"]')) {
      await page.click('[data-act="rp-b-print"]');
      await page.waitForTimeout(400);
      await shot("pdf_print");
      await page.evaluate(() => {
        FOCA.closeSheet();
        FOCA.reset(["/projects", "/p/reports", "/p/report-preview"]);
      });
    } else await page.click('[data-act="rp-b-open"]');
    await page.waitForTimeout(400);
    await shot("preview_after");
    await page.click('[data-act="rp-z:1"]');
    await page.click('[data-act="rp-z:1"]');
    await shot("preview_zoom");
  }
  if (only.includes("st")) {
    const m = await import(new URL("steps-st.mjs", import.meta.url).href);
    await m.default(page, { out, W, prep, shot, go });
  }
};
