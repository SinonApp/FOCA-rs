// Phone-side remediation checks on the demo backend: opt-in screenshot blocking, direct PDF export,
// report signature statuses. Each section prints "OK <label>" / "FAIL <label>" lines and a summary.
// Run: qa/shoot.sh --routes none --w 393 --out $PWD/qa/out/android-remediation \
//        --steps $PWD/qa/scenarios/android-remediation/steps.mjs   (AR=shots,pdf … limits the sections)
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

sections.shots = async (page, { go, shot }) => {
  await fresh(page, go);
  await go("/settings/security");
  const row = () =>
    page.evaluate(() => {
      const r = document.querySelector('[data-act="st-shots"]');
      const t = r && r.querySelector(".toggle");
      return r ? { text: r.innerText, on: !!(t && t.classList.contains("on")) } : null;
    });
  const r0 = await row();
  check("security: 'Block screenshots' row is shown", !!r0 && /скриншот/i.test(r0.text), JSON.stringify(r0));
  check("security: screenshots are allowed by default", r0 && !r0.on, JSON.stringify(r0));
  const s0 = await page.evaluate(() => FOCA.api.settings_get());
  check(
    "settings: block_shots is not set on a fresh install",
    !(s0.sec || {}).block_shots,
    JSON.stringify(s0.sec),
  );
  await shot("security_default");

  await page.click('[data-act="st-shots"] .body');
  await page.waitForTimeout(400);
  const s1 = await page.evaluate(() => FOCA.api.settings_get());
  check(
    "toggle on: sec.block_shots persisted as true",
    (s1.sec || {}).block_shots === true,
    JSON.stringify(s1.sec),
  );
  await go("/projects");
  await go("/settings/security");
  const r1 = await row();
  check("toggle on: survives navigation", r1 && r1.on, JSON.stringify(r1));

  await page.click('[data-act="st-shots"] .body');
  await page.waitForTimeout(400);
  const s2 = await page.evaluate(() => FOCA.api.settings_get());
  check(
    "toggle off: sec.block_shots persisted as false",
    (s2.sec || {}).block_shots === false,
    JSON.stringify(s2.sec),
  );
};

sections.pdf = async (page, { go, shot }) => {
  await go("/p/reports");
  const built = await page.evaluate(async () => {
    const r = await FOCA.api.report_build({
      tpl: "Полный",
      tpl_id: "full",
      fmt: "pdf",
      lang: "RU",
      sections: {},
    });
    return { id: r.id, name: r.name };
  });
  check("pdf: a report is built for the PDF format", !!built.id, JSON.stringify(built));
  await page.evaluate(id => FOCA.actions["rp-hmenu"](id), built.id);
  await page.waitForTimeout(300);
  check(
    "history menu: 'Get PDF' action for an HTML report",
    !!(await page.$(`[data-act="rp-h-pdf:${built.id}"]`)),
  );
  await page.click(`[data-act="rp-h-pdf:${built.id}"]`);
  await page.waitForTimeout(900);
  const sheet = await page.evaluate(() => {
    const d = document.querySelector(".sheet [data-pdf]");
    return {
      name: d && d.dataset.pdf,
      share: !!document.querySelector('.sheet [data-act="rp-pdf-share"]'),
    };
  });
  check(
    "pdf sheet: a .pdf file named after the report",
    !!sheet.name && sheet.name === built.name.replace(/\.[^.]+$/, ".pdf"),
    JSON.stringify(sheet),
  );
  check("pdf sheet: Share action", sheet.share);
  await shot("pdf_ready");
  await page.click('.sheet [data-act="rp-pdf-share"]');
  await page.waitForTimeout(300);
  await page.evaluate(() => FOCA.closeSheet());

  await go("/p/report-new");
  const labels = await page.evaluate(() => document.body.innerText);
  check(
    "report wizard: PDF format is not labelled as printing",
    !/PDF \(печать\)|через печать Android/.test(labels),
  );
};

sections.verify = async (page, { go, shot }) => {
  await go("/p/reports");
  const fp = "ab".repeat(32);
  const out = await page.evaluate(async fp => {
    const r = await FOCA.api.report_build({
      tpl: "Полный",
      tpl_id: "full",
      fmt: "html",
      lang: "RU",
      sections: {},
    });
    const orig = FOCA.api.report_verify;
    const base = await orig(r.id);
    const res = {};
    for (const st of ["verified_foreign", "verified_signed", "tampered"]) {
      FOCA.api.report_verify = async () => ({
        ...base,
        status: st,
        signature_alg: "ECDSA-P256-SHA256",
        signature_valid: st !== "tampered",
        signature_own_key: st === "verified_signed",
        key_fingerprint: fp,
      });
      FOCA.actions["rp-h-verify"](r.id);
      await new Promise(ok => setTimeout(ok, 400));
      const b = document.querySelector(".sheet [data-verify]");
      const f = document.querySelector(".sheet .rp-fp");
      res[st] = {
        cls: b ? b.className : "",
        text: b ? b.innerText : "",
        fp: f ? f.dataset.fp : null,
        sheet: document.querySelector(".sheet") ? document.querySelector(".sheet").innerText : "",
      };
      FOCA.closeSheet();
      await new Promise(ok => setTimeout(ok, 300));
    }
    FOCA.api.report_verify = orig;
    return res;
  }, fp);
  const f = out.verified_foreign;
  check(
    "verify: foreign key is shown as valid, not invalid",
    /ok/.test(f.cls) && /ключ не ваш/.test(f.text),
    JSON.stringify(f).slice(0, 300),
  );
  check(
    "verify: foreign key fingerprint is shown",
    f.fp === fp && /чужого ключа/.test(f.sheet),
    JSON.stringify(f).slice(0, 300),
  );
  check(
    "verify: own key keeps the device label",
    /ok/.test(out.verified_signed.cls) && /Подпись устройства/.test(out.verified_signed.text),
  );
  check("verify: tampered stays critical", /crit/.test(out.tampered.cls));
};

export default async (page, o) => {
  const only = (process.env.AR || Object.keys(sections).join(",")).split(",");
  const shot = async n => {
    await page.waitForTimeout(300);
    await page.screenshot({ path: `${o.out}/ar_${n}_${o.W}_fs${o.fsc}.png` });
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
