// "Paste from clipboard" buttons (API key sheet, launch wizard) and the clipboard helpers on the demo
// backend. The Android WebView cannot read the clipboard, so under Tauri F.clipRead goes through
// platform_clipboard_read (simulated here by stubbing FOCA.api with FOCA.isTauri on); the browser demo
// falls back to navigator.clipboard (stubbed per case). Checks the empty vs unreadable messages in
// RU/EN/UK, the native write with the sensitive flag and the native auto-clear.
// Run: qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/clipboard-paste/steps.mjs
const res = { ok: 0, fail: 0 };
const check = (label, cond, detail = "") => {
  if (cond) res.ok++;
  else res.fail++;
  console.log(`${cond ? "OK  " : "FAIL"} ${label}${!cond && detail ? " - " + detail : ""}`);
};

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

// Installs the page helpers once per page load: a browser clipboard stub and a native stub.
const helpers = page =>
  page.evaluate(() => {
    window.__clip = {
      browser(mode, value) {
        const st = { buf: value, writes: [] };
        Object.defineProperty(navigator, "clipboard", {
          configurable: true,
          value: {
            readText: async () => {
              if (mode === "deny") throw new DOMException("Read permission denied.", "NotAllowedError");
              return st.buf;
            },
            writeText: async t => {
              st.writes.push(t);
              st.buf = t;
            },
          },
        });
        FOCA.isTauri = false;
        return st;
      },
      native(read) {
        const st = { calls: [] };
        const orig = FOCA.__origApi || (FOCA.__origApi = { ...FOCA.api });
        FOCA.api.platform_clipboard_read = () => (st.calls.push(["read"]), Promise.resolve(read));
        FOCA.api.platform_clipboard_write = o => (st.calls.push(["write", o]), Promise.resolve({ ok: true }));
        FOCA.api.platform_clipboard_clear = o => (st.calls.push(["clear", o]), Promise.resolve({ ok: true, cleared: true }));
        st.restore = () => {
          Object.assign(FOCA.api, orig);
          FOCA.isTauri = false;
        };
        FOCA.isTauri = true;
        return st;
      },
      snack: () => (document.querySelector("#snack .sn-t") || {}).innerText || "",
    };
  });

const openKeySheet = async page => {
  await page.evaluate(() => FOCA.go("/settings/keys"));
  await page.waitForTimeout(300);
  await page.click('[data-act="st-key:vt"]');
  await page.waitForTimeout(300);
};

export default async (page, { go }) => {
  await fresh(page, go);
  await helpers(page);

  // --- API key sheet, browser fallback (demo sample disabled to see the real messages) ---
  await openKeySheet(page);
  const kb = await page.evaluate(async () => {
    const out = {};
    FOCA.isDemo = false;
    const kv = () => document.getElementById("st-kv");
    let st = __clip.browser("ok", "pasted-key-123");
    await FOCA.actions["st-kpaste"]();
    out.ok = { val: kv().value, buf: st.buf, snack: __clip.snack(), want: FOCA.t("settings.pasted_cleared") };
    kv().value = "";
    __clip.browser("ok", "   ");
    await FOCA.actions["st-kpaste"]();
    out.empty = { val: kv().value, snack: __clip.snack(), want: FOCA.t("settings.clip_empty") };
    __clip.browser("deny");
    await FOCA.actions["st-kpaste"]();
    out.deny = { val: kv().value, snack: __clip.snack(), want: FOCA.t("settings.clip_unreadable") };
    FOCA.isDemo = true;
    // The demo keeps its sample key when the browser refuses the read.
    await FOCA.actions["st-kpaste"]();
    out.demo = kv().value;
    return out;
  });
  check("key sheet: browser paste fills the key and clears the clipboard", kb.ok.val === "pasted-key-123" && kb.ok.buf === "" && kb.ok.snack === kb.ok.want, JSON.stringify(kb.ok));
  check("key sheet: empty clipboard says empty", kb.empty.val === "" && kb.empty.snack === kb.empty.want, JSON.stringify(kb.empty));
  check("key sheet: refused read says it could not read", kb.deny.val === "" && kb.deny.snack === kb.deny.want && kb.deny.want !== kb.empty.want, JSON.stringify(kb.deny));
  check("key sheet: demo falls back to the sample key", kb.demo.length > 10, kb.demo);

  // --- API key sheet, native path (Android) ---
  const kn = await page.evaluate(async () => {
    const out = {};
    FOCA.isDemo = false;
    const kv = () => document.getElementById("st-kv");
    let st = __clip.native({ ok: true, text: " native-key-9 ", available: true });
    await FOCA.actions["st-kpaste"]();
    out.ok = { val: kv().value, calls: st.calls, snack: __clip.snack(), want: FOCA.t("settings.pasted_cleared") };
    st.restore();
    kv().value = "";
    st = __clip.native({ ok: false, text: "", available: false, error: "no_focus" });
    await FOCA.actions["st-kpaste"]();
    out.focus = { val: kv().value, snack: __clip.snack(), want: FOCA.t("settings.clip_unreadable") };
    st.restore();
    st = __clip.native({ ok: true, text: "", available: false });
    await FOCA.actions["st-kpaste"]();
    out.empty = { snack: __clip.snack(), want: FOCA.t("settings.clip_empty") };
    st.restore();
    // Unsupported native layer (desktop) falls back to navigator.clipboard.
    __clip.browser("ok", "desktop-key");
    st = __clip.native({ ok: false, unsupported: true });
    await FOCA.actions["st-kpaste"]();
    out.desk = kv().value;
    st.restore();
    FOCA.isDemo = true;
    return out;
  });
  check(
    "key sheet: native read fills the key and clears natively",
    kn.ok.val === "native-key-9" && kn.ok.snack === kn.ok.want && JSON.stringify(kn.ok.calls) === '[["read"],["clear",{}]]',
    JSON.stringify(kn.ok),
  );
  check("key sheet: native read without focus says it could not read", kn.focus.val === "" && kn.focus.snack === kn.focus.want, JSON.stringify(kn.focus));
  check("key sheet: native empty clipboard says empty", kn.empty.snack === kn.empty.want, JSON.stringify(kn.empty));
  check("key sheet: unsupported native layer falls back to the browser API", kn.desk === "desktop-key", kn.desk);
  await page.evaluate(() => FOCA.closeSheet());

  // --- copy and auto-clear helpers ---
  const cp = await page.evaluate(async () => {
    FOCA.CLIP_CLEAR_MS = 60;
    let st = __clip.native(null);
    await FOCA.clipCopy("s3cr3t", { sensitive: true });
    await FOCA.clipCopy("plain");
    await new Promise(r => setTimeout(r, 150));
    const native = st.calls;
    st.restore();
    st = __clip.native(null);
    await FOCA.clipClear("s3cr3t");
    await FOCA.clipWrite("link");
    const clear = st.calls;
    st.restore();
    const b = __clip.browser("ok", "");
    await FOCA.clipCopy("browser-secret", { sensitive: true });
    const before = b.buf;
    await new Promise(r => setTimeout(r, 150));
    FOCA.CLIP_CLEAR_MS = 30000;
    return { native, clear, before, after: b.buf };
  });
  check(
    "clipCopy: native write carries the sensitive flag and the native clear delay, no JS timer",
    JSON.stringify(cp.native) ===
      '[["write",{"text":"s3cr3t","sensitive":true,"clear_after_ms":60}],["write",{"text":"plain","sensitive":false,"clear_after_ms":60}]]',
    JSON.stringify(cp.native),
  );
  check(
    "clipClear/clipWrite: native clear passes the expected value, plain write has no auto-clear",
    JSON.stringify(cp.clear) ===
      '[["clear",{"expected":"s3cr3t"}],["write",{"text":"link","sensitive":false,"clear_after_ms":0}]]',
    JSON.stringify(cp.clear),
  );
  check("clipCopy: browser fallback writes and auto-clears", cp.before === "browser-secret" && cp.after === "", JSON.stringify(cp));

  // --- launch wizard ---
  await page.evaluate(() => FOCA.go("/new"));
  await page.waitForTimeout(400);
  const la = await page.evaluate(async () => {
    const out = {};
    FOCA.isDemo = false;
    const txt = () => FOCA.page().innerText;
    __clip.browser("ok", "clip-one.example\nclip-two.example");
    await FOCA.actions["la-paste"]();
    await new Promise(r => setTimeout(r, 100));
    out.ok = { has: txt().includes("clip-one.example") && txt().includes("clip-two.example"), snack: __clip.snack(), want: FOCA.t("launch.clip_pasted") };
    __clip.browser("ok", "");
    await FOCA.actions["la-paste"]();
    out.empty = { snack: __clip.snack(), want: FOCA.t("launch.clip_empty") };
    __clip.browser("deny");
    await FOCA.actions["la-paste"]();
    out.deny = { snack: __clip.snack(), want: FOCA.t("launch.clip_unreadable") };
    const st = __clip.native({ ok: true, text: "native-target.example", available: true });
    await FOCA.actions["la-paste"]();
    await new Promise(r => setTimeout(r, 100));
    out.native = { has: txt().includes("native-target.example"), calls: st.calls };
    st.restore();
    const s2 = __clip.native({ ok: false, text: "", error: "blocked" });
    await FOCA.actions["la-paste"]();
    out.blocked = { snack: __clip.snack(), want: FOCA.t("launch.clip_unreadable") };
    s2.restore();
    FOCA.isDemo = true;
    return out;
  });
  check("launch: browser paste adds the targets", la.ok.has && la.ok.snack === la.ok.want, JSON.stringify(la.ok));
  check("launch: empty clipboard says empty", la.empty.snack === la.empty.want, JSON.stringify(la.empty));
  check("launch: refused read says it could not read", la.deny.snack === la.deny.want && la.deny.want !== la.empty.want, JSON.stringify(la.deny));
  check("launch: native read adds the target", la.native.has && JSON.stringify(la.native.calls) === '[["read"]]', JSON.stringify(la.native));
  check("launch: native blocked read says it could not read", la.blocked.snack === la.blocked.want, JSON.stringify(la.blocked));

  // --- unreadable message in every language ---
  const langs = await page.evaluate(async () => {
    const out = {};
    for (const l of ["en", "uk", "ru"]) {
      await FOCA.i18n.setLang(l);
      out[l] = [FOCA.t("settings.clip_unreadable"), FOCA.t("launch.clip_unreadable")];
    }
    return out;
  });
  const vals = Object.values(langs).flat();
  check(
    "unreadable messages are translated (RU/EN/UK) and differ from 'empty'",
    vals.every(v => v && !v.includes("clip_unreadable") && !v.includes("\u2014")) &&
      langs.en[0].startsWith("Could not read") &&
      langs.uk[0].startsWith("Не вдалося") &&
      langs.ru[0].startsWith("Не удалось"),
    JSON.stringify(langs),
  );

  console.log(`${res.ok} OK, ${res.fail} FAIL`);
};
