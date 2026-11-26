// UI remediation checks on the demo backend: app protection, escaping, toolbox/report/docs flows,
// layout of previews and cards. Each section prints "OK <label>" / "FAIL <label>" lines and a summary.
// Run: qa/shoot.sh --routes none --w 393 --out $PWD/qa/out/ui-remediation \
//        --steps $PWD/qa/scenarios/ui-remediation/steps.mjs   (UR=lock,xss … limits the sections)
const sections = {};
const res = { ok: 0, fail: 0 };
const check = (label, cond, detail = "") => {
  if (cond) res.ok++;
  else res.fail++;
  console.log(`${cond ? "OK  " : "FAIL"} ${label}${!cond && detail ? " - " + detail : ""}`);
};

// Fresh demo state with terms accepted and the welcome screen skipped.
const fresh = async (page, go) => {
  await go("/projects");
  await page.evaluate(() => {
    localStorage.clear();
    localStorage.setItem("foca-welcomed", "1");
  });
  await page.waitForTimeout(100);
  await go("/projects");
  await page.evaluate(async () => {
    const t = await FOCA.api.terms_get();
    if (!t.accepted) await FOCA.api.terms_accept(t.version);
  });
  await go("/projects");
};
const cur = page => page.evaluate(() => FOCA.current());
const typePin = async (page, pin) => {
  for (const d of pin) await page.click(`[data-act="st-lk:${d}"]`);
  await page.waitForTimeout(800);
};

sections.lock = async (page, { go, shot }) => {
  await fresh(page, go);
  check("no PIN: app starts without the lock screen", (await cur(page)) === "/projects");
  await page.evaluate(() => FOCA.api.pin_set("2580"));
  await page.waitForTimeout(200); // demo state is saved with a short debounce
  await go("/projects");
  check(
    "PIN set: start opens /lock",
    (await cur(page)) === "/lock" && !!(await page.$(".st-lock")),
    await cur(page),
  );
  await shot("lock_on_start");
  await typePin(page, "2580");
  check("correct PIN unlocks to the start screen", (await cur(page)) === "/projects", await cur(page));

  await page.evaluate(() => FOCA.api.settings_set({ sec: { autolock: "1" } }));
  check(
    "autolock: 30 s idle keeps the app open",
    (await page.evaluate(() => FOCA.autolock._idle(30000))) === false,
  );
  check(
    "autolock: 61 s idle opens /lock",
    (await page.evaluate(() => FOCA.autolock._idle(61000))) && (await cur(page)) === "/lock",
  );
  await typePin(page, "2580");
  check(
    "autolock: back from background after 30 s stays open",
    (await page.evaluate(() => FOCA.autolock._resume(30000))) === false,
  );
  check(
    "autolock: back from background after 70 s locks",
    (await page.evaluate(() => FOCA.autolock._resume(70000))) && (await cur(page)) === "/lock",
  );
  await typePin(page, "2580");

  // Panic PIN dialog passes the second argument to pin_set.
  await page.evaluate(() => FOCA.go("/settings/security"));
  await page.waitForTimeout(300);
  await page.click('[data-act="st-t:sec.panic"]');
  await page.waitForTimeout(300);
  check("panic toggle opens the setup dialog", !!(await page.$("#st-pp-cur")));
  await page.fill("#st-pp-cur", "2580");
  await page.fill("#st-pp-new", "1111");
  await page.fill("#st-pp-rep", "1111");
  await shot("panic_dialog");
  await page.click('[data-act="st-panic-save"]');
  await page.waitForTimeout(500);
  const pp = await page.evaluate(() => ({
    hash: !!FOCA_DEMO_BACKEND._state().settings.sec.panic_hash,
    on: !!FOCA.db.settings.sec.panic,
  }));
  check("panic PIN stored by the backend and switched on", pp.hash && pp.on, JSON.stringify(pp));

  // Clipboard: secrets are wiped after 30 s; st-kpaste clears the clipboard.
  const clip = await page.evaluate(async () => {
    let buf = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async t => {
          buf = t;
        },
        readText: async () => buf,
      },
    });
    FOCA.CLIP_CLEAR_MS = 50;
    await FOCA.clipCopy("s3cr3t-value");
    const before = buf;
    await new Promise(r => setTimeout(r, 150));
    const after = buf;
    await FOCA.clipCopy("other");
    buf = "user copied something else";
    await new Promise(r => setTimeout(r, 150));
    return { before, after, foreign: buf };
  });
  check(
    "copied secret is wiped after the timeout",
    clip.before === "s3cr3t-value" && clip.after === "",
    JSON.stringify(clip),
  );
  check("a newer foreign clipboard value is kept", clip.foreign === "user copied something else");
  await page.evaluate(() => FOCA.go("/settings/keys"));
  await page.waitForTimeout(300);
  await page.click('[data-act="st-key:vt"]');
  await page.waitForTimeout(300);
  const pasted = await page.evaluate(async () => {
    let buf = "pasted-key-123";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async t => {
          buf = t;
        },
        readText: async () => buf,
      },
    });
    await FOCA.actions["st-kpaste"]();
    return { val: document.getElementById("st-kv").value, buf };
  });
  check(
    "st-kpaste inserts the key and clears the clipboard",
    pasted.val === "pasted-key-123" && pasted.buf === "",
    JSON.stringify(pasted),
  );
  await page.evaluate(() => FOCA.closeSheet());
  await page.evaluate(() => localStorage.clear());
};

sections.lockkeys = async (page, { go }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.go("/lock"));
  await page.waitForTimeout(300);
  await page.evaluate(() => {
    FOCA.render(true);
    FOCA.render(true);
  });
  await page.waitForTimeout(300);
  await page.keyboard.press("1");
  await page.waitForTimeout(100);
  const dots = await page.evaluate(() => document.querySelectorAll(".st-lock #st-dots i.on").length);
  check("/lock re-mount keeps a single keydown listener (one key → one digit)", dots === 1, "dots=" + dots);
};

// Navigation requested while the PIN lock is up (notification route pushed by MainActivity, async
// F.reset from /open/:id, multi-step back, tab switch) is queued and runs only after the PIN.
sections.lockroute = async (page, { go }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.api.pin_set("2580"));
  await page.waitForTimeout(200);
  await go("/projects");
  // A project other than the one already open, so "not opened" is observable.
  const pid = await page.evaluate(() =>
    Object.keys(FOCA_DEMO_BACKEND._state().projects).find(
      id => !FOCA.db.project || id !== FOCA.db.project.id,
    ),
  );
  const state = () =>
    page.evaluate(() => ({
      route: FOCA.current(),
      overlay: !!document.querySelector(".st-lock"),
      project: FOCA.db.project ? FOCA.db.project.id : null,
    }));
  await page.evaluate(id => FOCA.go("/open/" + id), pid); // what MainActivity.pushRoute evaluates
  await page.waitForTimeout(800);
  let s = await state();
  check(
    "locked: notification route keeps /lock on top, project not opened",
    s.route === "/lock" && s.overlay && s.project !== pid,
    JSON.stringify(s),
  );
  await page.evaluate(() => {
    FOCA.reset(["/p/overview"]);
    FOCA.tab("/p/findings");
    FOCA.back(3);
  });
  await page.waitForTimeout(500);
  s = await state();
  check(
    "locked: F.reset / F.tab / multi-step back do not leave /lock",
    s.route === "/lock" && s.overlay && s.project !== pid,
    JSON.stringify(s),
  );
  await page.evaluate(id => FOCA.go("/open/" + id), pid); // the latest request wins
  await typePin(page, "2580");
  await page.waitForTimeout(800);
  s = await state();
  check(
    "after unlock: the queued notification route opens the project",
    s.route === "/p/overview" &&
      !s.overlay &&
      (await page.evaluate(() => FOCA.db.project && FOCA.db.project.id)) === pid,
    JSON.stringify(s),
  );
  // Autolock over an open screen: later navigation also waits for the PIN.
  await page.evaluate(() => FOCA.autolock.lockNow());
  await page.waitForTimeout(300);
  await page.evaluate(() => FOCA.go("/settings"));
  await page.waitForTimeout(300);
  check("autolock: navigation stays queued under /lock", (await cur(page)) === "/lock");
  await typePin(page, "2580");
  check("autolock: unlock replays the queued route", (await cur(page)) === "/settings", await cur(page));
  await page.evaluate(() => localStorage.clear());
};

// Core strings on the monitor screen (webhook rejection reason in the alert log, scan profile in the
// scan history and the diff picker) are text, not markup.
sections.monitorxss = async (page, { go }) => {
  await fresh(page, go);
  const pid = await page.evaluate(() => Object.keys(FOCA_DEMO_BACKEND._state().projects)[0]);
  await page.evaluate(id => FOCA.api.project_open(id), pid);
  const P = n => `<img src=x onerror=__x(${n})>`;
  await page.evaluate(
    async ([p1, p2, p3]) => {
      window.__hits = [];
      window.__x = n => window.__hits.push(n);
      // Shape of an alert log entry as stored by the core.
      const entry = {
        at: "2026-11-25T10:00:00",
        scan_id: "s1",
        count: 1,
        dropped: 0,
        alerts: [],
        deliveries: [
          { ok: false, channel: "webhook" + p2, status: 400, attempts: 1, sent: 0, error: "HTTP 400 " + p1 },
        ],
      };
      FOCA.db.scans.forEach(x => (x.profile = String(x.profile || "") + p3));
      FOCA.emit("db", {});
      FOCA.go("/p/monitor"); // loads the alert config of the project
      await new Promise(r => setTimeout(r, 400));
      const v2 = FOCA.state.v2;
      v2.alertCfg = Object.assign({}, v2.alertCfg || (FOCA.db.settings || {}).alerts || {}, {
        history: [entry],
      });
      FOCA.render(true);
    },
    [P(1), P(2), P(3)],
  );
  await page.waitForTimeout(600);
  const log = await page.evaluate(() =>
    [...document.querySelectorAll(".row .s")].map(e => e.textContent).find(t => t.includes("HTTP 400")),
  );
  check("alert log shows the webhook error as text", !!log && log.includes("<img"), String(log));
  await page.evaluate(() => FOCA.go("/p/diff"));
  await page.waitForTimeout(400);
  await page.evaluate(() => FOCA.actions["v2d-pick"]("a"));
  await page.waitForTimeout(400);
  const hits = await page.evaluate(() => [...new Set(window.__hits)]);
  const imgs = await page.evaluate(() => document.querySelectorAll('img[src="x"]').length);
  check(
    "monitor / diff: no markup injected from core strings",
    !hits.length && !imgs,
    JSON.stringify({ hits, imgs }),
  );
  await page.evaluate(() => FOCA.closeSheet());
};

// Document statuses after an in-app language switch (same snapshot, no project reopen): labels follow the
// language, the status filter counts and filters by status code.
sections.docslang = async (page, { go }) => {
  await fresh(page, go);
  const pid = await page.evaluate(() => Object.keys(FOCA_DEMO_BACKEND._state().projects)[0]);
  await page.evaluate(id => FOCA.api.project_open(id), pid);
  await page.evaluate(() => FOCA.go("/p/data/docs"));
  await page.waitForTimeout(400);
  await page.evaluate(() => FOCA.i18n.setLang("en"));
  await page.waitForTimeout(600);
  await page.evaluate(() => FOCA.go("/p/data/docs"));
  await page.waitForTimeout(400);
  const r = await page.evaluate(async () => {
    const live = FOCA.db.docs.filter(d => !d.deleted);
    const analyzed = live.filter(d => d.status_code === "analyzed");
    FOCA.actions["dd-filters"]();
    await new Promise(r => setTimeout(r, 300));
    const chips = [...document.querySelectorAll('[data-g="status"] .chip')].map(c => ({
      v: c.dataset.v,
      l: c.firstChild.textContent.trim(),
      n: +c.querySelector(".c").textContent,
    }));
    document.querySelector('[data-g="status"] .chip[data-v="analyzed"]').click();
    await new Promise(r => setTimeout(r, 100));
    FOCA.actions["dd-f-apply"]();
    await new Promise(r => setTimeout(r, 400));
    const pill = (document.querySelector(".dt-active .dt-fchip span") || {}).textContent || "";
    FOCA.actions["dd-reset"]();
    return {
      label: analyzed[0] && analyzed[0].status,
      chips,
      sum: chips.reduce((a, c) => a + c.n, 0),
      live: live.length,
      analyzed: analyzed.length,
      pill,
    };
  });
  check("docs: status label follows the language", r.label === "Analyzed", JSON.stringify(r.label));
  const an = r.chips.find(c => c.v === "analyzed") || {};
  check(
    "docs filter: status counts add up after a language switch",
    an.l === "Analyzed" && an.n === r.analyzed && r.sum === r.live,
    JSON.stringify(r.chips),
  );
  check("docs filter: active status chip is translated", r.pill === "Analyzed", r.pill);
  await page.evaluate(() => FOCA.i18n.setLang("ru"));
  await page.waitForTimeout(400);
};

// Untrusted values (search history, CVE ids from documents, file extensions) must not inject markup.
sections.xss = async (page, { go }) => {
  await fresh(page, go);
  const P = n => `x"><img src=x onerror=__x(${n})>`;
  await page.evaluate(() => {
    window.__hits = [];
    window.__x = n => window.__hits.push(n);
  });
  await page.evaluate(p => {
    FOCA.state.search = { q: "", chip: "all", recent: [p] };
    FOCA.go("/p/search");
  }, P(1));
  await page.waitForTimeout(400);
  const act = await page.evaluate(
    () => (document.querySelector('[data-act^="gset:"]') || {}).dataset?.act || "",
  );
  check("search history keeps the raw query inside data-act", act === "gset:" + P(1), act);
  const fid = await page.evaluate(p => {
    const f = FOCA.db.findings.find(x => x.cve && x.cve.length) || FOCA.db.findings[0];
    f.cve = [p];
    return f.id;
  }, P(2));
  await page.evaluate(id => FOCA.go("/p/finding/" + id), fid);
  await page.waitForTimeout(400);
  const cve = await page.evaluate(
    () => (document.querySelector('[data-act^="fd-cve:"]') || {}).textContent || "",
  );
  check("finding CVE id is rendered as text", cve.includes("<img"), cve);
  await page.evaluate(p => {
    FOCA.state.launch.files = [{ name: "a.txt", ext: p, sub: "1 КБ" }];
    FOCA.go("/new");
  }, P(3));
  await page.waitForTimeout(400);
  await page.evaluate(() => FOCA.render(true));
  await page.waitForTimeout(300);
  const hits = await page.evaluate(() => window.__hits);
  check("no injected handler ran (search, CVE, file extension)", hits.length === 0, JSON.stringify(hits));
  check(
    "no injected <img> elements",
    (await page.evaluate(() => document.querySelectorAll('img[src="x"]').length)) === 0,
  );
};

// Toolbox "Clean metadata" cleans the local file by path and opens the before/after screen.
sections.tbxclean = async (page, { go, shot }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.go("/tools"));
  await page.waitForTimeout(300);
  const calls = await page.evaluate(async () => {
    const seen = [];
    const orig = FOCA.api.doc_clean_file,
      orig2 = FOCA.api.doc_clean;
    FOCA.api.doc_clean_file = (...a) => {
      seen.push(["file", ...a.slice(0, 2)]);
      return orig(...a);
    };
    FOCA.api.doc_clean = (...a) => {
      seen.push(["ids", a[0]]);
      return orig2(...a);
    };
    await FOCA.actions["tbx-demo-file"]();
    await new Promise(r => setTimeout(r, 400));
    FOCA.actions["tbx-clean-file"]();
    await new Promise(r => setTimeout(r, 500));
    return seen;
  });
  check(
    "toolbox clean calls doc_clean_file(path, name)",
    calls.length === 1 &&
      calls[0][0] === "file" &&
      /contract\.docx$/.test(calls[0][1]) &&
      calls[0][2] === "contract.docx",
    JSON.stringify(calls),
  );
  check("toolbox clean opens /clean/result", (await cur(page)) === "/clean/result", await cur(page));
  await shot("tbx_clean_result");
};

// report_verify statuses of the core map to labelled banners (no raw status ids on screen).
sections.verify = async (page, { go, shot }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.go("/p/reports"));
  await page.waitForTimeout(300);
  const tones = {
    verified_signed: "ok",
    verified_hash: "ok",
    tampered: "crit",
    unsigned: "warn",
    missing: "crit",
  };
  for (const [status, tone] of Object.entries(tones)) {
    const r = await page.evaluate(async status => {
      const hid = (FOCA.db.reports || [])[0]?.id;
      const orig = FOCA.api.report_verify;
      FOCA.api.report_verify = async id => ({
        ...(await orig(id)),
        status,
        ok: status.startsWith("verified"),
      });
      FOCA.actions["rp-h-verify"](String(hid));
      await new Promise(r => setTimeout(r, 300));
      FOCA.api.report_verify = orig;
      const b = document.querySelector(".sheet [data-verify]");
      return { cls: b ? b.className : "", text: b ? b.innerText : "" };
    }, status);
    check(
      `verify ${status}: ${tone} banner with a label`,
      r.cls.includes(tone) && r.text && !r.text.includes(status),
      JSON.stringify(r),
    );
    if (status === "tampered") await shot("verify_tampered");
    await page.evaluate(() => FOCA.closeSheet());
    await page.waitForTimeout(200);
  }
};

// Route event, safe URL decoding, backend notices, plugin toggle rollback, no demo plugin file in production.
sections.misc = async (page, { go }) => {
  await fresh(page, go);
  const routeEv = await page.evaluate(async () => {
    const seen = [];
    FOCA.on("route", d => seen.push(d.path));
    FOCA.go("/settings");
    await new Promise(r => setTimeout(r, 200));
    return seen;
  });
  check("router emits a route event on navigation", routeEv.includes("/settings"), JSON.stringify(routeEv));
  // Shared files that arrived under the lock screen open after it is left.
  const shared = await page.evaluate(async () => {
    FOCA.go("/lock");
    await new Promise(r => setTimeout(r, 200));
    const orig = FOCA.api.platform_shared_files;
    FOCA.api.platform_shared_files = async () => ({
      files: [{ path: "/demo/cache/contract.docx", name: "contract.docx" }],
      skipped: 0,
    });
    FOCA.emit("shared", {});
    await new Promise(r => setTimeout(r, 200));
    const under = FOCA.current();
    // Leave the lock screen the only allowed way: the (demo) PIN.
    for (const d of "1234") FOCA.actions["st-lk"](d);
    await new Promise(r => setTimeout(r, 900));
    FOCA.api.platform_shared_files = orig;
    return { under, after: FOCA.current() };
  });
  check(
    "shared files wait under /lock and open after it",
    shared.under === "/lock" && shared.after === "/shared",
    JSON.stringify(shared),
  );
  check(
    "malformed %-escape does not throw",
    await page.evaluate(() => FOCA.decode("a%zz") === "a%zz" && FOCA.decode("a%20b") === "a b"),
  );
  await page.evaluate(() => FOCA.go("/p/doc/%E0%A4%A"));
  await page.waitForTimeout(300);
  check(
    "route with a malformed escape still renders",
    await page.evaluate(() => !!document.querySelector(".page")),
  );
  const notice = await page.evaluate(async () => {
    FOCA.notice({
      kind: "interrupted",
      text: "Скан был прерван системой: продолжите его на экране скана",
      project: FOCA.cur && FOCA.db.project && FOCA.db.project.id,
    });
    await new Promise(r => setTimeout(r, 200));
    const s = document.getElementById("snack");
    return { text: s.innerText, show: s.classList.contains("show") };
  });
  check(
    "backend notice is shown as a snackbar",
    notice.show && notice.text.includes("прерван"),
    JSON.stringify(notice),
  );
  // Core plugin toggle rolls back on IPC error.
  await page.evaluate(() => FOCA.go("/settings/plugins"));
  await page.waitForTimeout(400);
  const roll = await page.evaluate(async () => {
    const el = document.querySelector('[data-act^="v2p-core-on:"]');
    if (!el) return { none: true };
    const before = el.classList.contains("on");
    const orig = FOCA.api.plugin_toggle;
    FOCA.api.plugin_toggle = () => Promise.reject(new Error("ipc down"));
    FOCA.actions["v2p-core-on"](el.dataset.act.split(":")[1], el);
    await new Promise(r => setTimeout(r, 200));
    FOCA.api.plugin_toggle = orig;
    return { before, after: el.classList.contains("on") };
  });
  check(
    "core plugin toggle rolls back on IPC error",
    !roll.none && roll.before === roll.after,
    JSON.stringify(roll),
  );
  const prod = await page.evaluate(async () => {
    FOCA.isDemo = false;
    let clicked = null;
    const oc = HTMLInputElement.prototype.click;
    HTMLInputElement.prototype.click = function () {
      clicked = this.type + " " + this.accept;
    };
    FOCA.actions["v2p-install"]();
    HTMLInputElement.prototype.click = oc;
    FOCA.isDemo = true;
    const sheet = document.querySelector(".sheet.show");
    return { clicked, demoFile: !!(sheet && sheet.innerText.includes("nuclei-lite.wasm")) };
  });
  check(
    "production plugin install opens a file chooser, not the demo .wasm",
    prod.clicked && prod.clicked.startsWith("file") && !prod.demoFile,
    JSON.stringify(prod),
  );
};

// Report preview pages grow with their content (nothing clipped) and the page scrolls to the end;
// the same for /clean/result. Run at 360/393 px and --fs 2.
sections.preview = async (page, { go, shot }) => {
  await fresh(page, go);
  const clipped = async () =>
    page.evaluate(() =>
      [...document.querySelectorAll(".rp-paper")]
        .map((p, i) => {
          const pi = p.querySelector(".rp-pi");
          const r = p.getBoundingClientRect();
          const inner = pi
            ? [...pi.querySelectorAll("*")].reduce((m, e) => Math.max(m, e.getBoundingClientRect().bottom), 0)
            : 0;
          return inner > r.bottom + 1
            ? `page ${i + 1}: content ${Math.round(inner - r.bottom)}px below the sheet`
            : null;
        })
        .filter(Boolean),
    );
  for (const r of ["/p/report-preview", "/p/report-new"]) {
    await page.evaluate(r => FOCA.reset(["/projects", "/p/reports", r]), r);
    await page.waitForTimeout(500);
    if (r === "/p/report-new") {
      const sh = await page.$(".rp-fixedp");
      if (!sh) continue;
    }
    // A page with far more text than an A4 sheet holds must grow, not clip.
    await page.evaluate(() => {
      const pi = document.querySelector(".rp-paper .rp-pi");
      if (pi)
        pi.insertAdjacentHTML(
          "beforeend",
          '<p class="qa-long">' + "Длинный абзац отчёта без переносов ".repeat(120) + "</p>",
        );
    });
    const c = await clipped();
    check(`${r}: no report page clips its content`, c.length === 0, c.slice(0, 3).join("; "));
    const sc = await page.evaluate(() => {
      const p = document.querySelector(".page");
      const s = document.querySelector(".rp-scroll");
      const el =
        s && s.scrollHeight > s.clientHeight + 2 && getComputedStyle(s).overflowY !== "visible" ? s : p;
      el.scrollTop = el.scrollHeight;
      const last = [...document.querySelectorAll(".rp-paper")].pop();
      return last ? last.getBoundingClientRect().bottom <= innerHeight + 2 : true;
    });
    check(`${r}: last report page can be scrolled into view`, sc);
  }
  await shot("preview_scrolled");
  // Before/after screen: every diff row is reachable by scrolling.
  await page.evaluate(() => FOCA.go("/tools"));
  await page.waitForTimeout(300);
  await page.evaluate(async () => {
    await FOCA.actions["tbx-demo-file"]();
    await new Promise(r => setTimeout(r, 400));
    FOCA.actions["tbx-clean-file"]();
    await new Promise(r => setTimeout(r, 500));
  });
  const ba = await page.evaluate(() => {
    const p = document.querySelector(".page");
    p.scrollTop = p.scrollHeight;
    const cut = [...document.querySelectorAll(".page *")]
      .filter(e => {
        const s = getComputedStyle(e);
        return (
          (s.overflowY === "hidden" || s.overflow === "hidden") &&
          e.scrollHeight > e.clientHeight + 2 &&
          e.innerText &&
          e.innerText.length > 40
        );
      })
      .map(e => e.className)
      .slice(0, 3);
    const touch = [...document.querySelectorAll(".hy-ba")].filter(r => {
      const k = r.querySelector(".k"),
        v = r.querySelector(".v");
      return k && v && k.getBoundingClientRect().right > v.getBoundingClientRect().left;
    }).length;
    return { cur: FOCA.current(), cut, sw: p.scrollWidth - p.clientWidth, touch };
  });
  check(
    "/clean/result: no clipped text blocks and no horizontal overflow",
    ba.cur === "/clean/result" && !ba.cut.length && ba.sw <= 0 && !ba.touch,
    JSON.stringify(ba),
  );
  await shot("clean_result_bottom");
};

// Project cards: score on one line, level label + icon inside the badge, long names ellipsised.
sections.pjcard = async (page, { go, shot }) => {
  await fresh(page, go);
  await page.evaluate(() => {
    const ps = (FOCA.projects || []).filter(x => !x.archived);
    if (ps[0]) {
      ps[0].risk = 100;
      ps[0].name = "Очень-длинное-название-проекта-для-проверки-переноса-и-многоточия." + ps[0].name;
    }
    if (ps[1]) ps[1].risk = null;
    FOCA.render(true);
  });
  await page.waitForTimeout(300);
  await page.evaluate(() => document.querySelector(".pj-card")?.scrollIntoView({ block: "center" }));
  await page.waitForTimeout(200);
  const r = await page.evaluate(() =>
    [...document.querySelectorAll(".pj-card")].slice(0, 6).map(c => {
      const badge = c.querySelector(".pj-risk"),
        b = badge.querySelector("b"),
        s = badge.querySelector("span");
      const br = badge.getBoundingClientRect(),
        sr = s.getBoundingClientRect();
      const lh = parseFloat(getComputedStyle(b).lineHeight) || 20;
      const name = c.querySelector(".pj-name");
      return {
        scoreLines: Math.round(b.getBoundingClientRect().height / lh),
        labelInside: sr.left >= br.left - 0.5 && sr.right <= br.right + 0.5,
        labelLines: Math.round(sr.height / (parseFloat(getComputedStyle(s).lineHeight) || 14)),
        cardOverflow: c.scrollWidth - c.clientWidth,
        nameLines: Math.round(
          name.getBoundingClientRect().height / (parseFloat(getComputedStyle(name).lineHeight) || 20),
        ),
      };
    }),
  );
  check("project cards found", r.length > 0);
  check(
    "risk score stays on one line",
    r.every(x => x.scoreLines === 1),
    JSON.stringify(r.map(x => x.scoreLines)),
  );
  check(
    "level label and icon stay inside the badge",
    r.every(x => x.labelInside),
    JSON.stringify(r.map(x => x.labelInside)),
  );
  check(
    "level label stays on one line",
    r.every(x => x.labelLines === 1),
    JSON.stringify(r.map(x => x.labelLines)),
  );
  check(
    "no horizontal overflow in project cards",
    r.every(x => x.cardOverflow <= 0),
    JSON.stringify(r.map(x => x.cardOverflow)),
  );
  check(
    "long project names are cut with an ellipsis (≤ 2 lines)",
    r.every(x => x.nameLines <= 2),
    JSON.stringify(r.map(x => x.nameLines)),
  );
  await shot("pj_cards");
};

// Logs export waits for device info, so device.txt is not a column of dashes.
sections.devlog = async (page, { go }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.go("/settings/debug"));
  await page.waitForTimeout(400);
  const dev = await page.evaluate(async () => {
    let got = null;
    const orig = FOCA.api.logs_export,
      sh = FOCA.api.platform_share;
    FOCA.api.logs_export = o => {
      got = o.device;
      return orig(o);
    };
    FOCA.api.platform_share = async () => ({ ok: true });
    FOCA.actions["dbg-share"]();
    await new Promise(r => setTimeout(r, 500));
    FOCA.api.logs_export = orig;
    FOCA.api.platform_share = sh;
    return got;
  });
  check(
    "logs export sends filled device info",
    !!dev && /Устройство: (?!-)\S/.test(dev) && /Android: (?!-)\S/.test(dev),
    String(dev).slice(0, 160),
  );
};

// Report builder: no sample executor company by default; full secrets need an explicit confirmation.
sections.rpdefaults = async (page, { go, shot }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.reset(["/projects", "/p/reports", "/p/report-new"]));
  await page.waitForTimeout(400);
  const d = await page.evaluate(() => ({
    company: document.getElementById("rp-company")?.value,
    secrets: FOCA.state.reports.d.secrets,
  }));
  check("executor company is empty by default", d.company === "", JSON.stringify(d));
  check("secrets are masked by default", d.secrets === "partial", JSON.stringify(d));
  await page.fill("#rp-company", "ТОВ «Тест Аудит»");
  await page.waitForTimeout(700);
  check(
    "entered executor is stored in settings for next reports",
    await page.evaluate(
      () => FOCA.db.settings.report && FOCA.db.settings.report.company === "ТОВ «Тест Аудит»",
    ),
  );
  await page.click('[data-act="rp-d:secrets:full"]');
  await page.waitForTimeout(200);
  const n0 = await page.evaluate(() => FOCA.db.reports.length);
  await page.click('[data-act="rp-build"]');
  await page.waitForTimeout(400);
  check("full secrets: warning sheet before building", !!(await page.$('[data-act="rp-build-full"]')));
  await shot("rp_full_secrets_warn");
  await page.click('[data-act="rp-build-masked"]');
  await page.waitForTimeout(4500);
  const after = await page.evaluate(() => ({
    n: FOCA.db.reports.length,
    secrets: FOCA.db.reports[0] && FOCA.db.reports[0].opts && FOCA.db.reports[0].opts.secrets,
  }));
  check(
    '"Маскировать" builds the report with masked secrets',
    after.n === n0 + 1 && after.secrets === "partial",
    JSON.stringify(after),
  );
  await page.evaluate(() => FOCA.closeSheet());
};

// /new "Import targets from file": production reads the chosen file, the demo sample stays demo-only.
sections.laimport = async (page, { go, shot }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.go("/new"));
  await page.waitForTimeout(400);
  const chooser = page.waitForEvent("filechooser", { timeout: 5000 });
  await page.evaluate(() => {
    FOCA.isDemo = false;
    FOCA.actions["la-import"]();
    FOCA.isDemo = true;
  });
  const fc = await chooser;
  await fc.setFiles({
    name: "my-scope.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("alpha-corp.ua\nportal.alpha-corp.ua\n10.1.2.3\n"),
  });
  await page.waitForTimeout(400);
  const sheet = await page.evaluate(() => document.querySelector(".sheet.show")?.innerText || "");
  check(
    "production import previews the chosen file",
    sheet.includes("my-scope.txt") && sheet.includes("portal.alpha-corp.ua") && !sheet.includes("-group.example"),
    sheet.slice(0, 200),
  );
  await shot("la_import_file");
  await page.click('[data-act="la-import-go"]');
  await page.waitForTimeout(300);
  const t = await page.evaluate(() =>
    FOCA.state.launch.targets.map(x => x.v || x.value || x.raw || JSON.stringify(x)).join(" "),
  );
  check(
    "targets from the chosen file are added",
    t.includes("alpha-corp.ua") && t.includes("10.1.2.3"),
    t.slice(0, 200),
  );
};

// /queue with the "full" profile asks for an explicit authorization before queueing.
sections.queue = async (page, { go, shot }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.go("/queue"));
  await page.waitForTimeout(400);
  const calls = [];
  await page.exposeFunction("__qcall", a => calls.push(a)).catch(() => {});
  await page.evaluate(() => {
    const orig = FOCA.api.queue_add;
    FOCA.api.queue_add = o => {
      window.__qcall(JSON.stringify(o));
      return orig(o);
    };
  });
  await page.click('[data-act="tbx-qprof:full"]');
  await page.waitForTimeout(200);
  await page.click('[data-act^="tbx-qpick:"]');
  await page.waitForTimeout(200);
  await page.click('[data-act="tbx-qadd"]');
  await page.waitForTimeout(400);
  check(
    "full profile: confirmation sheet, nothing queued yet",
    !!(await page.$("#tbx-qgo")) && calls.length === 0,
    String(calls.length),
  );
  check(
    "confirm button is disabled until authorization is ticked",
    await page.evaluate(() => document.getElementById("tbx-qgo").disabled),
  );
  await shot("queue_active_confirm");
  await page.click('.sheet [data-act="tbx-qcons"]');
  await page.click("#tbx-qgo");
  await page.waitForTimeout(400);
  check(
    "after authorization the project is queued with profile full",
    calls.length === 1 && JSON.parse(calls[0]).profile === "full",
    calls.join(),
  );
  await page.click('[data-act="tbx-qprof:passive"]');
  await page.waitForTimeout(200);
  await page.click('[data-act^="tbx-qpick:"]');
  await page.click('[data-act="tbx-qadd"]');
  await page.waitForTimeout(400);
  check(
    "passive profile is queued without a confirmation",
    calls.length === 2 && !(await page.$(".sheet.show #tbx-qgo")),
    calls.length,
  );
};

// .foca.enc import: the file comes from the system picker (platform_pick_files), not a typed path.
sections.encimport = async (page, { go, shot }) => {
  await fresh(page, go);
  const r = await page.evaluate(async () => {
    FOCA.actions["pj-import-enc"]();
    await new Promise(r => setTimeout(r, 300));
    const typed = !!document.getElementById("pj-imp-path");
    let picked = null;
    const orig = FOCA.api.platform_pick_files;
    FOCA.api.platform_pick_files = async o => {
      picked = o;
      return { files: [{ path: "/cache/pick/client.foca.enc", name: "client.foca.enc" }] };
    };
    FOCA.isDemo = false;
    FOCA.actions["pj-imp-pick"]();
    await new Promise(r => setTimeout(r, 200));
    FOCA.isDemo = true;
    FOCA.api.platform_pick_files = orig;
    let sent = null;
    const imp = FOCA.api.project_import_encrypted;
    FOCA.api.project_import_encrypted = async (path, pw) => {
      sent = { path, pw };
      throw new Error("stub");
    };
    document.getElementById("pj-imp-pw").value = "secret12";
    FOCA.actions["pj-import-enc-go"]();
    await new Promise(r => setTimeout(r, 200));
    FOCA.api.project_import_encrypted = imp;
    return { typed, picked, shown: document.getElementById("pj-imp-file")?.innerText || "", sent };
  });
  check("no free-text path field in the import sheet", !r.typed);
  check(
    "picker is called with multiple:false and the name is shown",
    r.picked && r.picked.multiple === false && r.shown.includes("client.foca.enc"),
    JSON.stringify(r),
  );
  check(
    "import receives the picked path",
    r.sent && r.sent.path === "/cache/pick/client.foca.enc",
    JSON.stringify(r.sent),
  );
  await shot("enc_import_sheet");
  await page.evaluate(() => FOCA.closeSheet());
};

// Document clean: real options reach doc_clean, no fake "Downloads" toast, the result screen opens.
sections.docclean = async (page, { go, shot }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.reset(["/projects", "/p/overview", "/p/doc/1"]));
  await page.waitForTimeout(400);
  await page.evaluate(() => FOCA.actions["dd-clean"]("1"));
  await page.waitForTimeout(300);
  await shot("doc_clean_sheet");
  const opts = await page.evaluate(() =>
    [...document.querySelectorAll('.sheet [data-act^="toggle-check:"]')].map(e => e.dataset.act),
  );
  check(
    "clean sheet lists the real doc_clean options",
    opts.includes("toggle-check:remove_javascript") && opts.length === 3,
    JSON.stringify(opts),
  );
  await page.click('.sheet [data-act="toggle-check:remove_javascript"]');
  const sent = await page.evaluate(async () => {
    let got = null;
    const orig = FOCA.api.doc_clean;
    FOCA.api.doc_clean = (ids, o) => {
      got = { ids, o };
      return orig(ids, o);
    };
    FOCA.actions["dd-clean-ok"]("1");
    await new Promise(r => setTimeout(r, 500));
    FOCA.api.doc_clean = orig;
    return { got, cur: FOCA.current(), snack: document.getElementById("snack").innerText };
  });
  check(
    "unticked option is passed as false",
    sent.got &&
      sent.got.o &&
      sent.got.o.remove_javascript === false &&
      sent.got.o.remove_embedded_files === true,
    JSON.stringify(sent.got),
  );
  check("cleaning opens /clean/result", sent.cur === "/clean/result", sent.cur);
  check('no false "saved to Downloads" toast', !/Загрузки/.test(sent.snack), sent.snack);
  const photo = await page.evaluate(() => {
    const d = FOCA.db.docs.find(x => /^(jpeg|png|heic|tiff?)$/i.test(x.ext));
    return d ? d.id : null;
  });
  if (photo) {
    await page.evaluate(id => {
      FOCA.reset(["/projects", "/p/overview", "/p/doc/" + id]);
    }, photo);
    await page.waitForTimeout(300);
    await page.evaluate(id => FOCA.actions["dd-clean"](String(id)), photo);
    await page.waitForTimeout(300);
    check(
      "EXIF note is shown for non-jpg photos too",
      await page.evaluate(() => /EXIF/.test(document.querySelector(".sheet.show").innerText)),
    );
    await page.evaluate(() => FOCA.closeSheet());
  }
};

// Report "Open" for CSV/JSON hands the file to the system; preview texts follow the report language.
sections.rpopen = async (page, { go, shot }) => {
  await fresh(page, go);
  await page.evaluate(() => FOCA.go("/p/reports"));
  await page.waitForTimeout(300);
  const shared = await page.evaluate(async () => {
    const st = FOCA.state.reports;
    const h = { ...(st.history[0] || FOCA.db.reports[0]), fmt: "csv", id: 99901, name: "Data_x_v9.csv" };
    st.history.unshift(h);
    let got = null;
    const sh = FOCA.shareSheet;
    FOCA.shareSheet = name => {
      got = name;
    };
    FOCA.actions["rp-open"]("99901");
    await new Promise(r => setTimeout(r, 200));
    FOCA.shareSheet = sh;
    st.history.shift();
    return got;
  });
  check(
    "Open on a CSV report hands the file to the share/open chooser",
    shared === "Data_x_v9.csv",
    String(shared),
  );
  const prevText = async (tpl, lang) =>
    page.evaluate(
      async ([tpl, lang]) => {
        const d = FOCA.state.reports.d || {};
        Object.assign(d, { tpl, lang });
        FOCA.state.reports.prevOf = null;
        FOCA.reset(["/projects", "/p/reports", "/p/report-preview"]);
        await new Promise(r => setTimeout(r, 400));
        return document.querySelector(".page").innerText;
      },
      [tpl, lang],
    );
  await page.evaluate(() => FOCA.go("/p/report-new"));
  await page.waitForTimeout(300);
  const en = await prevText("compliance", "EN");
  check(
    "fixed-template preview in EN has no RU table header or caveat",
    /Finding/.test(en) && !/Находка|Стандарты|заключение экспертизы/.test(en),
    en.slice(0, 300),
  );
  const ua = await prevText("executive", "UA");
  check(
    "fixed-template preview in UA uses UA texts",
    /Знахідка|Знахідок/.test(ua) && !/Находка|Находок, отвечающих/.test(ua),
    ua.slice(0, 300),
  );
  const full = await prevText("full", "EN");
  check("severity chart includes Info", /\bInfo\b/.test(full), full.slice(0, 200));
  check(
    "non-RU preview explains that the file uses the report language",
    /на языке отчёта/.test(full),
  );
  await shot("rp_preview_en");
  await page.evaluate(() => Object.assign(FOCA.state.reports.d, { tpl: "full", lang: "UA" }));
};

// Settings: no invented DNS/Wi-Fi/PIN-date values, no dummy buttons, real key deletion, AI screen.
sections.stfakes = async (page, { go, shot }) => {
  await fresh(page, go);
  const textOf = async r => {
    await page.evaluate(r => FOCA.reset(["/projects", "/settings", r]), r);
    await page.waitForTimeout(400);
    return page.evaluate(() => document.querySelector(".page").innerText);
  };
  const net = await textOf("/settings/network");
  check(
    "network: no invented resolver/Wi-Fi names",
    !/Office-5G|one\.one\.one\.one|1\.1\.1\.1/.test(net) && /Системный резолвер Android/.test(net),
  );
  const power = await textOf("/settings/power");
  check(
    "power: no fake traffic reset button",
    !(await page.$('[data-act="st-treset"]')) && !/Сбросить счётчик/.test(power),
  );
  await textOf("/settings/battery");
  check("battery: no fake background test button", !(await page.$('[data-act="st-btest"]')));
  const secT = await textOf("/settings/security");
  check("security: no invented PIN date", !/12\.10\.2026|установлен \d/.test(secT), secT.slice(0, 200));
  await page.evaluate(() => FOCA.go("/settings/keys"));
  await page.waitForTimeout(300);
  const del = await page.evaluate(async () => {
    const id = Object.keys(FOCA.state.settings.keys).find(k => FOCA.state.settings.keys[k].v);
    if (!id) return { none: true };
    FOCA.actions["st-kdel"](id);
    await new Promise(r => setTimeout(r, 200));
    return {
      action: !!document.querySelector("#snack .sn-a"),
      text: document.getElementById("snack").innerText,
    };
  });
  check(
    "key delete has no fake Undo",
    !del.none && !del.action && /удалён/.test(del.text),
    JSON.stringify(del),
  );
  const how = await page.evaluate(async () => {
    let buf = null;
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async t => {
          buf = t;
        },
        readText: async () => buf,
      },
    });
    FOCA.isDemo = false;
    FOCA.actions["st-khow"]("vt");
    FOCA.isDemo = true;
    await new Promise(r => setTimeout(r, 100));
    return { buf, snack: document.getElementById("snack").innerText };
  });
  check(
    '"How to get a key" copies the link in the app',
    /^https:\/\//.test(how.buf || "") && /скопирована/.test(how.snack),
    JSON.stringify(how),
  );
  await page.evaluate(() => FOCA.reset(["/projects", "/settings", "/settings/ai"]));
  await page.waitForTimeout(400);
  check("AI settings: no reveal button for a masked key", !(await page.$('[data-act="v2mo-eye:v2ai-k"]')));
  const noProj = await page.evaluate(async () => {
    const p = FOCA.db.project;
    FOCA.db.project = null;
    FOCA.render(true);
    await new Promise(r => setTimeout(r, 200));
    const has = !!document.querySelector('[data-act="go:/p/ai"]');
    FOCA.db.project = p;
    FOCA.render(true);
    return has;
  });
  check('AI settings: no "Go to summary" without an open project', noProj === false);
  await shot("st_network");
};

// Document errors show the real reason (or none), never a hard-coded 403, and name what failed by
// error_kind: parse → "Parse error / could not be processed", download/http → "Download error",
// no kind (older core) → neutral "Processing error".
sections.docerr = async (page, { go }) => {
  await fresh(page, go);
  const r = await page.evaluate(async () => {
    const d = FOCA.db.docs.find(x => x.status_code === "error") || FOCA.db.docs[0];
    const view = async (kind, err) => {
      Object.assign(d, { status_code: "error", stc: "bad", err, error_kind: kind });
      if (kind == null) delete d.error_kind;
      FOCA.reset(["/projects", "/p/overview", "/p/doc/" + d.id]);
      await new Promise(r => setTimeout(r, 400));
      return document.querySelector(".page").innerText;
    };
    return {
      http: await view("http", "HTTP 404 · Not Found"),
      download: await view("download", ""),
      parse: await view("parse", "bad zip header"),
      none: await view(null, ""),
    };
  });
  check(
    "document error shows the real HTTP status",
    /HTTP 404/.test(r.http) && !/403/.test(r.http) && /Ошибка загрузки/.test(r.http),
    r.http.slice(0, 300),
  );
  check(
    "download error without a reason invents no code",
    !/403/.test(r.download) && /не удалось скачать/.test(r.download),
    r.download.slice(0, 300),
  );
  check(
    "parse error is not called a download error",
    /Ошибка разбора/.test(r.parse) &&
      /не удалось обработать \(bad zip header\)/.test(r.parse) &&
      !/скачать|Ошибка загрузки/.test(r.parse),
    r.parse.slice(0, 300),
  );
  check(
    "error without error_kind uses the neutral label",
    /Ошибка обработки/.test(r.none) && !/скачать|Ошибка загрузки/.test(r.none),
    r.none.slice(0, 300),
  );
};

// Toolbox/queue IPC failures surface as messages (no unhandled rejections); dd-to-report counts the saved set.
sections.ipc = async (page, { go, errs }) => {
  await fresh(page, go);
  const unhandled = [];
  page.on("pageerror", e => unhandled.push(e.message));
  await page.evaluate(() => FOCA.go("/tools"));
  await page.waitForTimeout(300);
  const r = await page.evaluate(async () => {
    const rej = () => Promise.reject(new Error("ipc down"));
    const keep = {};
    for (const k of [
      "tool_log",
      "queue_pause",
      "queue_resume",
      "queue_remove",
      "queue_clear",
      "platform_pick_files",
    ]) {
      keep[k] = FOCA.api[k];
      FOCA.api[k] = rej;
    }
    const seen = [];
    window.addEventListener("unhandledrejection", e => seen.push(String(e.reason && e.reason.message)));
    FOCA.actions["tbx-tab"]("log");
    FOCA.actions["tbx-reload-log"]();
    FOCA.actions["tbx-pick-file"]();
    FOCA.actions["tbx-qpause"]();
    FOCA.actions["tbx-qresume"]();
    FOCA.actions["tbx-qdel"]("1");
    FOCA.actions["tbx-qclear"]();
    await new Promise(r => setTimeout(r, 400));
    Object.assign(FOCA.api, keep);
    return { seen, snack: document.getElementById("snack").innerText };
  });
  check(
    "toolbox/queue IPC errors are handled (no unhandled rejections)",
    r.seen.length === 0,
    JSON.stringify(r.seen),
  );
  check("an IPC error is reported to the user", /ipc down/.test(r.snack), r.snack);
  // dd-to-report: the total must count the new selection even when settings update later (async core).
  const cnt = await page.evaluate(async () => {
    FOCA.reset(["/projects", "/p/overview", "/p/doc/1"]);
    await new Promise(r => setTimeout(r, 300));
    const doc = FOCA.db.docs.find(d => FOCA.sel.related("doc", d.id).findings.length);
    if (!doc) return { none: true };
    const orig = FOCA.api.settings_set;
    FOCA.api.settings_set({ report: { picked: { [FOCA.db.project.id]: [] } } });
    await new Promise(r => setTimeout(r, 100));
    let release;
    FOCA.api.settings_set = p =>
      new Promise(res => {
        release = () => res(orig(p));
      });
    FOCA.actions["dd-to-report"](String(doc.id));
    await new Promise(r => setTimeout(r, 100));
    const before = document.getElementById("snack").innerText;
    release();
    await new Promise(r => setTimeout(r, 200));
    FOCA.api.settings_set = orig;
    const n = FOCA.sel.related("doc", doc.id).findings.length;
    return { before, after: document.getElementById("snack").innerText, n };
  });
  check(
    "dd-to-report: total counts the saved selection",
    !cnt.none && new RegExp(`всего в выборке ${cnt.n}\\b`).test(cnt.after),
    JSON.stringify(cnt),
  );
};

export default async (page, o) => {
  const only = (process.env.UR || Object.keys(sections).join(",")).split(",");
  const shot = async n => {
    await page.waitForTimeout(300);
    await page.screenshot({ path: `${o.out}/ur_${n}_${o.W}_fs${o.fsc}.png` });
  };
  for (const name of only) {
    if (!sections[name]) continue;
    try {
      await sections[name](page, { ...o, shot });
    } catch (e) {
      check(`section ${name} finished`, false, e.message.split("\n")[0]);
    }
  }
  console.log(`${res.ok} OK, ${res.fail} FAIL`);
};
