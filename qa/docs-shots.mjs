// Screenshots for the README and the docs: the UI in demo mode on a 393×852 phone (device scale 3, dark theme),
// one set per language, saved as WebP into docs/assets/screenshots/<lang>/NN-name.webp, plus the composed
// banner docs/assets/banner.png (1280×640, also used as the GitHub social preview).
//
//   qa/docs-shots.sh                                  # all shots, en + uk, plus the banner
//   qa/docs-shots.sh --langs en --only 03,04          # a subset
//   qa/docs-shots.sh --out $PWD/qa/out/docs-shots     # somewhere else (default: docs/assets)
//   flags: --no-banner, --quality 0.8 (WebP quality), --png (also keep the raw PNGs next to the WebP files)
//
// The demo data is fictional: reserved documentation domains (RFC 2606), addresses (RFC 5737) and AS numbers
// (RFC 5398). Finding texts are rendered by the UI in the language of each set, as in the app.
const { chromium } = (await import(process.env.PW_CORE || "playwright-core")).default;
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { demoFindings } from "./demo-locales.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const arg = k => {
  const i = process.argv.indexOf("--" + k);
  return i > 0 ? process.argv[i + 1] : null;
};
const has = k => process.argv.includes("--" + k);
const OUT = path.resolve(arg("out") || path.join(ROOT, "docs/assets"));
const LANGS = (arg("langs") || "en,uk").split(",");
const ONLY = arg("only") ? arg("only").split(",") : null;
const QUALITY = +(arg("quality") || 0.8);
const W = 393,
  H = 852,
  DSF = 3;
const LOCALE = { en: "en-US", uk: "uk-UA", ru: "ru-RU" };

// Help articles and the UI dictionary as the core serves them (the demo backend has only short stubs).
const help = {},
  ui = {};
for (const l of ["en", "ru", "uk"]) {
  help[l] = JSON.parse(fs.readFileSync(path.join(ROOT, "locales", l, "help.json"), "utf8"));
  ui[l] = JSON.parse(fs.readFileSync(path.join(ROOT, "locales", l, "ui.json"), "utf8"));
  const dir = path.join(ROOT, "locales", l, "ui");
  if (fs.existsSync(dir))
    for (const f of fs
      .readdirSync(dir)
      .filter(f => f.endsWith(".json"))
      .sort())
      Object.assign(ui[l], JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")));
}

const findingsCat = demoFindings(ROOT);

// The shots. `go` is a route or an async function (page, helpers) that prepares the screen.
const SHOTS = [
  // A target typed but not added yet.
  { id: "01", name: "new-project", go: "/new", type: ["#la-in", "testphp.vulnweb.com"] },
  { id: "02", name: "scan", go: "scan" },
  { id: "03", name: "findings", go: "/p/findings" },
  { id: "04", name: "finding-detail", go: "/p/finding/1" },
  // Scrolled to the secrets and metadata blocks.
  { id: "05", name: "document-metadata", go: "/p/doc/1", scrollTo: ".page .sec-h", nth: 1, offset: 8 },
  { id: "06", name: "people-graph", go: "/p/graph" },
  { id: "07", name: "network", go: "/p/data/hosts" },
  { id: "08", name: "timeline", go: "/p/timeline" },
  { id: "09", name: "report", go: "report" },
  // Scrolled to "Network and device": background work card and the About row with the beta chip.
  {
    id: "10",
    name: "settings",
    go: "/settings",
    scrollTo: '[data-act="st-go:/settings/network"]',
    offset: 60,
  },
];

const b = await chromium.launch({ args: ["--disable-gpu", "--disable-dev-shm-usage"] });
const errors = [];
const made = {};

// WebP encoding inside Chromium (no image library needed).
const enc = await (await b.newContext()).newPage();
const toWebp = async (png, q) =>
  Buffer.from(
    await enc.evaluate(
      async ([b64, q]) => {
        const img = new Image();
        img.src = "data:image/png;base64," + b64;
        await img.decode();
        const c = document.createElement("canvas");
        c.width = img.naturalWidth;
        c.height = img.naturalHeight;
        c.getContext("2d").drawImage(img, 0, 0);
        const blob = await new Promise(r => c.toBlob(r, "image/webp", q));
        const buf = new Uint8Array(await blob.arrayBuffer());
        let s = "";
        for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode(...buf.subarray(i, i + 0x8000));
        return btoa(s);
      },
      [png.toString("base64"), q],
    ),
    "base64",
  );

for (const lang of LANGS) {
  const ctx = await b.newContext({
    viewport: { width: W, height: H },
    deviceScaleFactor: DSF,
    isMobile: true,
    hasTouch: true,
    locale: LOCALE[lang] || lang,
    colorScheme: "dark",
  });
  await ctx.addInitScript(
    ([h, u, f]) => {
      window.FOCA_DEMO_HELP = h;
      window.FOCA_DEMO_UI = u;
      window.FOCA_DEMO_FINDINGS = f;
    },
    [help, ui, findingsCat],
  );
  const p = await ctx.newPage();
  p.on("pageerror", e => errors.push(`${lang}: ${e.message}`));
  p.on("console", m => m.type() === "error" && errors.push(`${lang}: ${m.text()}`));
  const base = new URL("../ui/index.html#", import.meta.url).href;
  const ev = (f, a) => p.evaluate(f, a);
  const wait = ms => p.waitForTimeout(ms);
  const ready = () =>
    p.waitForFunction(() => window.FOCA && FOCA.cur && document.querySelector(".page"), null, {
      timeout: 15000,
    });
  const prep = () =>
    ev(() => {
      FOCA.setTheme("dark");
      window.__setInsets(32, 20, 0, 0);
    });

  // Fresh demo state, terms accepted, welcome seen.
  await p.goto(base + "/projects");
  await ready();
  await ev(() => {
    FOCA.api.demo_reset();
    FOCA.api.terms_accept("1");
    localStorage.setItem("foca-welcomed", "1");
  });
  await wait(300);
  await p.goto("about:blank");
  await p.goto(base + "/projects");
  await ready();
  await ev(l => {
    FOCA.i18n.setLang(l);
    FOCA.api.project_open("contoso");
  }, lang);
  await wait(300);
  await prep();

  const helpers = {
    // One demo scan step while the demo timer stays paused.
    step: n =>
      ev(n => {
        FOCA.api.scan_resume();
        window.FOCA_DEMO_BACKEND._ff(n);
        FOCA.api.scan_pause();
      }, n),
  };
  const special = {
    // Scan in progress: standard profile, paused in metadata extraction (done and running stages, live sources).
    async scan() {
      await ev(() => FOCA.api.scan_start({ project: "contoso", profile: "std" }));
      await ev(() => FOCA.api.scan_pause());
      for (let k = 0; k < 80; k++) {
        const st = await ev(() => FOCA.api.scan_status().then(s => s.stage));
        if (st === "meta") break;
        await helpers.step(1);
      }
      await helpers.step(3);
      await ev(() => FOCA.go("/p/scan"));
    },
    // Report preview in the language of the set (the draft defaults to Ukrainian).
    async report() {
      await ev(() => FOCA.go("/p/report-new"));
      await wait(500);
      const code = lang === "en" ? "EN" : lang === "uk" ? "UA" : "RU";
      await ev(c => {
        const b = document.querySelector(`[data-act="rp-d:lang:${c}"]`);
        if (b) b.click();
      }, code);
      await wait(300);
      await ev(() => FOCA.go("/p/report-preview"));
    },
  };

  const dir = path.join(OUT, "screenshots", lang);
  fs.mkdirSync(dir, { recursive: true });
  made[lang] = [];
  // The scan shot changes the demo state, so it runs last.
  const order = [...SHOTS.filter(s => s.go !== "scan"), ...SHOTS.filter(s => s.go === "scan")];
  for (const s of order) {
    if (ONLY && !ONLY.includes(s.id)) continue;
    if (typeof s.go === "string" && !special[s.go]) await ev(r => FOCA.go(r), s.go);
    else await special[s.go]();
    await wait(900);
    if (s.type) await p.fill(s.type[0], s.type[1]);
    await prep();
    await ev(
      ([sel, off, nth]) => {
        const pg = FOCA.page() || document.scrollingElement;
        const el = sel && document.querySelectorAll(sel)[nth];
        pg.scrollTo(
          0,
          el ? el.getBoundingClientRect().top - pg.getBoundingClientRect().top + pg.scrollTop - off : 0,
        );
      },
      [s.scrollTo || null, s.offset || 0, s.nth || 0],
    );
    await wait(400);
    // The English set must not show Cyrillic (UI text or demo data) or em dashes anywhere in the viewport.
    const bad = await ev(l => {
      const out = [];
      const re = l === "en" ? /[\u0400-\u04ff]|\u2014/ : /\u2014/;
      const seen = el => {
        const r = el.getBoundingClientRect();
        const cs = getComputedStyle(el);
        return r.width > 0 && r.height > 0 && r.bottom > 0 && r.top < innerHeight && cs.visibility !== "hidden";
      };
      const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let n; (n = w.nextNode()); ) {
        const t = n.nodeValue.trim();
        if (t && re.test(t) && n.parentElement && seen(n.parentElement)) out.push(t.slice(0, 80));
      }
      return [...new Set(out)];
    }, lang);
    for (const t of bad) errors.push(`${lang} ${s.id}: ${t}`);
    const png = await p.screenshot({ type: "png" });
    const webp = await toWebp(png, QUALITY);
    const file = path.join(dir, `${s.id}-${s.name}.webp`);
    fs.writeFileSync(file, webp);
    if (has("png")) fs.writeFileSync(file.replace(/\.webp$/, ".png"), png);
    made[lang].push({ file: path.relative(ROOT, file), kb: Math.round(webp.length / 1024) });
  }
  await ctx.close();
}

// Banner: logo, name, tagline and three phone shots from the English set.
if (!has("no-banner") && LANGS.includes("en")) {
  const pick = ["03-findings", "05-document-metadata", "02-scan"].map(n =>
    path.join(OUT, "screenshots/en", n + ".webp"),
  );
  if (pick.every(f => fs.existsSync(f))) {
    const data = f => "data:image/webp;base64," + fs.readFileSync(f).toString("base64");
    const logo =
      "data:image/png;base64," + fs.readFileSync(path.join(ROOT, "ui/icon.png")).toString("base64");
    const inter = f => "file://" + path.join(ROOT, "ui/fonts", f);
    const html = `<!doctype html><html><head><style>
      @font-face { font-family: Inter; src: url("${inter("Inter-Regular.ttf")}"); font-weight: 400; }
      @font-face { font-family: Inter; src: url("${inter("Inter-SemiBold.ttf")}"); font-weight: 600; }
      html, body { margin: 0; width: 1280px; height: 640px; overflow: hidden; }
      body { font-family: Inter, sans-serif; color: #e8ecf3;
        background: radial-gradient(circle at 78% 40%, #1d2b4a 0, #0d1320 55%, #090d16 100%); position: relative; }
      .txt { position: absolute; left: 64px; top: 0; bottom: 0; width: 490px; display: flex; flex-direction: column; justify-content: center; }
      .logo { display: flex; align-items: center; gap: 20px; margin-bottom: 26px; }
      .logo img { width: 84px; height: 84px; }
      h1 { font-size: 60px; font-weight: 600; margin: 0; letter-spacing: -1px; }
      .tag { font-size: 28px; line-height: 1.3; font-weight: 600; margin: 0 0 18px; }
      .sub { font-size: 19px; line-height: 1.5; color: #a9b4c8; margin: 0 0 26px; }
      .chips { display: flex; gap: 10px; flex-wrap: wrap; }
      .chips span { font-size: 16px; padding: 7px 14px; border-radius: 999px; border: 1px solid #33415c; color: #c9d3e4; background: #121a2b; }
      .phones { position: absolute; right: 44px; top: 0; bottom: 0; display: flex; align-items: center; gap: 18px; }
      .ph { width: 190px; height: 412px; border-radius: 28px; padding: 6px; background: #1b2232; box-shadow: 0 18px 50px rgba(0,0,0,.55), 0 0 0 1px #2c3650; }
      .ph img { width: 100%; height: 100%; border-radius: 23px; object-fit: cover; object-position: top; display: block; }
      .ph.mid { transform: translateY(-22px); }
    </style></head><body>
      <div class="txt">
        <div class="logo"><img src="${logo}"><h1>FOCA-rs</h1></div>
        <p class="tag">OSINT and document metadata recon on your Android phone</p>
        <p class="sub">Passive-first scans, offline analysis and reports mapped to security standards.</p>
        <div class="chips"><span>Rust core</span><span>Offline reports</span><span>GPL-3.0</span></div>
      </div>
      <div class="phones">
        <div class="ph"><img src="${data(pick[0])}"></div>
        <div class="ph mid"><img src="${data(pick[1])}"></div>
        <div class="ph"><img src="${data(pick[2])}"></div>
      </div>
    </body></html>`;
    const tmp = path.join(ROOT, "qa/out/docs-shots");
    fs.mkdirSync(tmp, { recursive: true });
    fs.writeFileSync(path.join(tmp, "banner.html"), html);
    const bp = await (
      await b.newContext({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: 1 })
    ).newPage();
    await bp.goto("file://" + path.join(tmp, "banner.html"));
    await bp.waitForTimeout(500);
    const file = path.join(OUT, "banner.png");
    await bp.screenshot({ path: file, type: "png" });
    made.banner = { file: path.relative(ROOT, file), kb: Math.round(fs.statSync(file).size / 1024) };
  } else errors.push("banner: the English shots 02, 03 and 05 are missing");
}

console.log(JSON.stringify({ errors, made }, null, 1));
await b.close();
