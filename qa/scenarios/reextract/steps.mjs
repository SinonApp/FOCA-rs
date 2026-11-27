// Re-analysis of stored documents: the update banner (and "not now" remembered per project and
// revision), the sheet with options and the traffic estimate, progress, the before/after summary,
// cancel with an interrupted run that continues, and "Re-analyse" from the Documents selection
// mode. Fails on horizontal overflow in the banner and the sheet.
export default async (page, ctx) => {
  const log = [];
  try {
    await run(page, ctx, log);
  } finally {
    console.error(JSON.stringify(log));
  }
};
const run = async (page, { out, W, prep }, log) => {
  const shot = async n => {
    await page.waitForTimeout(350);
    await page.screenshot({ path: `${out}/step_${n}_${W}.png` });
  };
  const ev = (f, a) => page.evaluate(f, a);
  const check = (name, ok, info = "") => {
    log.push({ name, ok, info });
    console.log(`${ok ? "OK  " : "FAIL"} ${name}${info ? ` (${info})` : ""}`);
  };
  const open = async r => {
    await page.goto("about:blank");
    await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r);
    await page.waitForTimeout(250);
    await prep();
    await page.waitForTimeout(400);
  };
  const overflow = () =>
    ev(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  const sheetOverflow = () =>
    ev(() => {
      const s = document.querySelector(".rx-sheet");
      if (!s) return -1;
      return [...s.querySelectorAll("*")].filter(
        e => e.getBoundingClientRect().right > s.getBoundingClientRect().right + 1,
      ).length;
    });
  const sheetText = () => ev(() => (document.querySelector(".rx-sheet") || {}).innerText || "");
  const waitFor = async (f, ms = 15000) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) {
      if (await ev(f)) return true;
      await page.waitForTimeout(150);
    }
    return false;
  };

  await open("/p/overview");
  const pid = await ev(() => FOCA.db.project.id);
  // Six documents analysed by an older extraction (two of them without a stored file).
  const aged = await ev(p => {
    const B = window.FOCA_DEMO_BACKEND;
    const ids = B._state()
      .projects[p].docs.filter(d => !d.deleted && (d.status === "analyzed" || d.status === "error"))
      .map(d => d.id)
      .filter(id => id % 5 === 0)
      .slice(0, 2);
    const more = B._state()
      .projects[p].docs.filter(d => !d.deleted && d.status === "analyzed" && d.id % 5 !== 0)
      .map(d => d.id)
      .slice(0, 4);
    localStorage.removeItem("foca-reextract-dismiss:" + p);
    return B._reextractAge(p, ids.concat(more));
  }, pid);
  check("six documents aged", aged.outdated.total === 6, JSON.stringify(aged.outdated));
  await page.waitForTimeout(400);
  await open("/p/overview");
  await waitFor(() => !!document.querySelector("#rx-banner"));
  const banner = await ev(() => (document.querySelector("#rx-banner") || {}).innerText || "");
  check("update banner shows the count", /Переанализировать 6 документов/.test(banner), banner.slice(0, 120));
  check("overview entry row present", await ev(() => !!document.querySelector(".rx-ov")));
  check("overview has no horizontal overflow", (await overflow()) <= 1);
  await shot("01_banner");

  await page.click('[data-act="rx-dismiss"]');
  await page.waitForTimeout(300);
  check("not now hides the banner", !(await ev(() => !!document.querySelector("#rx-banner"))));
  await open("/p/overview");
  await page.waitForTimeout(600);
  check("dismissal remembered after reload", !(await ev(() => !!document.querySelector("#rx-banner"))));
  await ev(p => localStorage.removeItem("foca-reextract-dismiss:" + p), pid);
  await open("/p/overview");
  await waitFor(() => !!document.querySelector("#rx-banner"));

  await page.click('#rx-banner [data-act="rx-open:outdated"]');
  await waitFor(() => !!document.querySelector(".rx-sheet .rx-opts"));
  let t = await sheetText();
  check("sheet explains no new search", t.includes("Новый поиск не запускается"));
  check("sheet names the outdated documents", t.includes("документы прошлой версии: 6"), t.slice(0, 300));
  await page.click('[data-act="rx-mode:stored_and_missing"]');
  await page.waitForTimeout(200);
  t = await sheetText();
  check("traffic warning with a size", /Трафик: до [\d,]+ (КБ|МБ)/.test(t));
  check("sheet has no overflow (options)", (await sheetOverflow()) === 0);
  await shot("02_options");

  await page.click('[data-act="rx-start"]');
  check("progress appears", await waitFor(() => !!document.querySelector(".rx-prog"), 3000));
  await shot("03_progress");
  check("result appears", await waitFor(() => !!document.querySelector(".rx-diff"), 15000));
  t = await sheetText();
  check("summary counts parsed and downloaded", /4 разобрано заново · 2 скачано/.test(t), t.slice(0, 160));
  check(
    "diff lists documents with text and severities",
    t.includes("Документы с текстом") && t.includes("Критичные"),
  );
  check("link to findings", await ev(() => !!document.querySelector('[data-act="rx-findings"]')));
  check("sheet has no overflow (result)", (await sheetOverflow()) === 0);
  await shot("04_result");
  await page.click('[data-act="rx-findings"]');
  await page.waitForTimeout(500);
  check("link opens findings", await ev(() => FOCA.cur.path.startsWith("/p/finding")));

  await open("/p/overview");
  await page.waitForTimeout(600);
  check("banner gone after the run", !(await ev(() => !!document.querySelector("#rx-banner"))));

  // Cancel a full run from Data > Documents: the interrupted run continues next time.
  await open("/p/data/docs");
  await page.click('[data-act="rx-open"]');
  await waitFor(() => !!document.querySelector(".rx-sheet .rx-opts"));
  await page.click('[data-act="rx-start"]');
  await waitFor(() => !!document.querySelector(".rx-prog"), 3000);
  await page.waitForTimeout(500);
  await page.click('[data-act="rx-cancel"]');
  check(
    "cancel returns to the options",
    await waitFor(() => !!document.querySelector(".rx-sheet .rx-pend"), 5000),
  );
  t = await sheetText();
  check(
    "interrupted run offered to continue",
    t.includes("Прошлый запуск прерван") && t.includes("Продолжить"),
  );
  await shot("05_cancelled");
  await ev(() => FOCA.closeSheet());

  // Selection mode: re-analyse two selected documents.
  await ev(() => FOCA.actions["dd-sel-start"]());
  await page.waitForTimeout(300);
  await page.click(".dt-doc >> nth=0");
  await page.click(".dt-doc >> nth=1");
  check(
    "selection bar has the re-analyse action",
    await ev(() => !!document.querySelector('[data-act="dd-bulk:rx"]')),
  );
  check("selection bar has no overflow", (await overflow()) <= 1);
  await shot("06_selection");
  await page.click('[data-act="dd-bulk:rx"]');
  await waitFor(() => !!document.querySelector(".rx-sheet"));
  t = await sheetText();
  check(
    "sheet for the selection",
    t.includes("Выбрано: 2 документа") && !t.includes("Прошлый запуск прерван"),
    t.slice(0, 200),
  );
  await shot("07_sel_sheet");
  await ev(() => FOCA.closeSheet());
};
