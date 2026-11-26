// Layout sweep: visits every route in the longer UI languages at phone widths and font scales and
// reports layout defects: horizontal page overflow, clipped text without an ellipsis, input text
// wider than its field, elements cut at a clipping container's edge or sticking out of their parent,
// and overlapping sibling controls/labels.
//   Also finds Russian text (ы э ъ ё) on EN/UK screens ("ru-text"); cases not in qa/layout-sweep-ru.txt fail.
//   node qa/layout-sweep.mjs [--langs uk,en] [--widths 360,393] [--fs 1,2] [--routes /a,/b] [--out qa/out/layout-sweep]
// Writes report.json and report.md to the output dir; exits 1 when an issue is not in the allow-list.
// Playwright: PW_CORE (path to playwright-core/index.js, see qa/local.env) or the package from node_modules.
const { chromium } = (await import(process.env.PW_CORE || "playwright-core")).default;
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { demoFindings } from "./demo-locales.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf("--" + k); return i > 0 ? process.argv[i + 1] : d; };
const list = (k, d) => arg(k, d).split(",").filter(Boolean);
const LANGS = list("langs", "uk,en"), WIDTHS = list("widths", "360,393").map(Number), FSS = list("fs", "1,2").map(Number);
const OUT = path.resolve(arg("out", path.join(ROOT, "qa/out/layout-sweep")));
fs.mkdirSync(OUT, { recursive: true });

// Routes: qa/routes.txt plus router entries that file does not list. /lock goes last (it locks navigation).
const EXTRA = ["/help", "/help/set-fuzz", "/tools", "/queue", "/p/data", "/p/preflight", "/p/attack-paths", "/settings/sources", "/settings/licenses"];
let ROUTES = arg("routes", "") ? list("routes", "") : [...new Set([...fs.readFileSync(path.join(ROOT, "qa/routes.txt"), "utf8").split(/[\s,]+/).filter(Boolean), ...EXTRA])];
ROUTES = [...ROUTES.filter(r => r !== "/lock"), ...ROUTES.filter(r => r === "/lock")];

// Intentional cases: { kind, sel (RegExp on the element path), route? (RegExp), why }.
const ALLOW = [
  { kind: "text-spill", sel: /span\.v2t-hh$/, why: "timeline heat map: hour labels centred over narrow columns on purpose" },
];

// Same bundles as qa/shoot.mjs: help articles and the merged UI dictionary per language.
const help = {}, ui = {};
for (const l of ["en", "ru", "uk"]) {
  help[l] = JSON.parse(fs.readFileSync(path.join(ROOT, "locales", l, "help.json"), "utf8"));
  ui[l] = JSON.parse(fs.readFileSync(path.join(ROOT, "locales", l, "ui.json"), "utf8"));
  const dir = path.join(ROOT, "locales", l, "ui");
  if (fs.existsSync(dir)) for (const f of fs.readdirSync(dir).filter(f => f.endsWith(".json")).sort()) Object.assign(ui[l], JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")));
}
const findingsCat = demoFindings(ROOT);

// Russian text on EN/UK screens: letters only Russian uses (ы э ъ ё) in visible text and in placeholder, title and
// aria-label. Reported as info (kind "ru-text") once per language, at the first width and font scale.
function detectRussian() {
  const RU = /[ыэъёЫЭЪЁ]/;
  const out = [];
  const seen = new Set();
  const path = e => {
    const parts = [];
    for (let a = e; a && a !== document.body && parts.length < 4; a = a.parentElement) {
      let s = a.tagName.toLowerCase();
      const c = [...a.classList].slice(0, 2);
      if (c.length) s += "." + c.join(".");
      parts.unshift(s);
    }
    return parts.join(" > ");
  };
  const shown = e => {
    if (!e.getClientRects().length) return false;
    for (let a = e; a && a !== document.body; a = a.parentElement) {
      const st = getComputedStyle(a);
      if (st.visibility === "hidden" || st.display === "none" || a.getAttribute("aria-hidden") === "true") return false;
    }
    return true;
  };
  const add = (e, text) => {
    const key = path(e) + "|" + text;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind: "ru-text", sel: path(e), text: text.replace(/\s+/g, " ").trim().slice(0, 120), data: {} });
  };
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = w.nextNode(); n; n = w.nextNode())
    if (RU.test(n.nodeValue) && n.parentElement && !/^(SCRIPT|STYLE)$/.test(n.parentElement.tagName) && shown(n.parentElement)) add(n.parentElement, n.nodeValue);
  for (const e of document.querySelectorAll("[placeholder],[title],[aria-label]"))
    for (const a of ["placeholder", "title", "aria-label"]) {
      const v = e.getAttribute(a);
      if (v && RU.test(v) && shown(e)) add(e, `${a}: ${v}`);
    }
  return out;
}

// In-page detector; returns a list of { kind, sel, text, data }.
function detect() {
  const vw = document.documentElement.clientWidth;
  const out = [];
  const seen = new Set();
  const cs = e => getComputedStyle(e);
  const visible = e => {
    if (!e.getClientRects().length) return false;
    const r = e.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    for (let a = e; a && a !== document.body; a = a.parentElement) {
      const s = cs(a);
      if (s.visibility === "hidden" || s.opacity === "0" || a.getAttribute("aria-hidden") === "true" || a.hasAttribute("inert")) return false;
    }
    return true;
  };
  const name = e => {
    let s = e.tagName.toLowerCase();
    if (e.id) s += "#" + e.id;
    const c = [...e.classList].filter(x => !/^(on|show|active|sel)$/.test(x)).slice(0, 3);
    if (c.length) s += "." + c.join(".");
    const act = e.getAttribute("data-act");
    if (act) s += `[data-act=${act.split(":")[0]}]`;
    return s;
  };
  const pathOf = e => { const p = []; for (let a = e; a && a !== document.body && p.length < 4; a = a.parentElement) p.unshift(name(a)); return p.join(" > "); };
  const text = e => (e.value || e.getAttribute("placeholder") || e.getAttribute("aria-label") || e.textContent || "").replace(/\s+/g, " ").trim().slice(0, 60);
  const add = (kind, e, data) => {
    const sel = pathOf(e), key = kind + "|" + sel + "|" + text(e);
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, sel, text: text(e), data });
  };
  const hasOwnText = e => [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
  const root = document.querySelector("#app") || document.body;
  const all = [...root.querySelectorAll("*")].filter(e => !e.closest("svg, canvas") || e.tagName === "svg" || e.tagName === "canvas");
  // Page-level horizontal overflow.
  const pg = document.querySelector(".page");
  if (document.documentElement.scrollWidth > vw + 1) out.push({ kind: "page-overflow", sel: "html", text: "", data: { sw: document.documentElement.scrollWidth, vw } });
  if (pg && pg.scrollWidth > pg.clientWidth + 1) out.push({ kind: "page-overflow", sel: ".page", text: "", data: { sw: pg.scrollWidth, cw: pg.clientWidth } });
  const vis = all.filter(visible);
  const scroller = e => { for (let a = e.parentElement; a && a !== document.body; a = a.parentElement) { const x = cs(a).overflowX; if ((x === "auto" || x === "scroll") && a !== pg) return a; } return null; };
  const canvasCtx = document.createElement("canvas").getContext("2d");
  for (const e of vis) {
    const s = cs(e), r = e.getBoundingClientRect();
    const tag = e.tagName;
    // Inputs: the value (or placeholder) wider than the text area of the field.
    if ((tag === "INPUT" && /^(text|search|number|email|url|tel|password|)$/.test(e.type)) || tag === "TEXTAREA") {
      if (tag === "INPUT") {
        const t = e.value || e.getAttribute("placeholder") || "";
        if (t) {
          canvasCtx.font = `${s.fontStyle} ${s.fontWeight} ${s.fontSize} ${s.fontFamily}`;
          const tw = canvasCtx.measureText(e.type === "password" && e.value ? "•".repeat(t.length) : t).width;
          const avail = e.clientWidth - parseFloat(s.paddingLeft) - parseFloat(s.paddingRight);
          // An ellipsis (text-overflow on the field) is an intentional cut: reported as info only.
          if (tw > avail + 1) add(s.textOverflow === "ellipsis" ? "input-ellipsis" : "input-text", e, { tw: Math.round(tw), avail: Math.round(avail), what: e.value ? "value" : "placeholder" });
        }
      }
      continue;
    }
    // Clipped text: horizontal overflow hidden/clip on an element with its own text, no ellipsis.
    if ((s.overflowX === "hidden" || s.overflowX === "clip") && e.clientWidth > 2 && e.scrollWidth > e.clientWidth + 1 && hasOwnText(e)) {
      if (s.textOverflow === "ellipsis") {
        if (!e.title && !e.getAttribute("aria-label") && !e.closest("[title],[aria-label]")) add("ellipsis-no-title", e, { sw: e.scrollWidth, cw: e.clientWidth });
      } else add("clipped-text", e, { sw: e.scrollWidth, cw: e.clientWidth });
    }
    // Unbreakable text running out of a visible-overflow block (long file names, URLs).
    if (s.overflowX === "visible" && s.display !== "inline" && e.clientWidth > 2 && e.scrollWidth > e.clientWidth + 1 && hasOwnText(e) && !scroller(e))
      add("text-spill", e, { sw: e.scrollWidth, cw: e.clientWidth });
    if (s.position === "fixed") continue;
    if (scroller(e)) continue; // inside an intentional horizontal scroller
    // Cut at the edge of a clipping ancestor (or the window).
    let clip = null;
    for (let a = e.parentElement; a && a !== document.body; a = a.parentElement) { const x = cs(a).overflowX; if (x !== "visible") { clip = a; break; } }
    const edge = clip ? Math.min(clip.getBoundingClientRect().right, vw) : vw;
    if (r.right > edge + 1 && r.left < edge) add("cut", e, { right: Math.round(r.right), edge: Math.round(edge), clip: clip ? name(clip) : "window" });
    // Sticking out of the parent box (parent with visible overflow and a box of its own).
    const p = e.parentElement;
    if (p && s.position !== "absolute" && p !== root) {
      const ps = cs(p), pr = p.getBoundingClientRect();
      if (ps.display !== "contents" && ps.display !== "inline" && ps.overflowX === "visible" && r.right > pr.right + 1.5 && (ps.borderRightWidth !== "0px" || ps.backgroundColor !== "rgba(0, 0, 0, 0)"))
        add("spill", e, { right: Math.round(r.right), parent: name(p), parentRight: Math.round(pr.right) });
    }
  }
  // Overlapping siblings among controls and labels in normal flow. Compares painted content: text line
  // boxes (a Range over the text) or the icon, not border boxes (tap targets grow with negative margins).
  const isItem = e => e.matches("button, a, input, select, textarea, label, [data-act], .pill, .chip, .tag, small, b, strong, span, h1, h2, h3, h4, p") && cs(e).position !== "absolute" && cs(e).position !== "fixed";
  const ink = e => {
    if (/^(INPUT|SELECT|TEXTAREA)$/.test(e.tagName)) return [e.getBoundingClientRect()];
    const rs = [];
    const rg = document.createRange();
    // Clip a rect by every overflow-clipping element from `from` up to `e` (line-clamped text keeps
    // rects for its hidden lines).
    const clipTo = (r, from) => {
      let l = r.left, t = r.top, rr = r.right, b = r.bottom;
      for (let a = from; a; a = a === e ? null : a.parentElement) {
        if (cs(a).overflow !== "visible") { const c = a.getBoundingClientRect(); l = Math.max(l, c.left); t = Math.max(t, c.top); rr = Math.min(rr, c.right); b = Math.min(b, c.bottom); }
      }
      return { left: l, top: t, right: rr, bottom: b, width: rr - l, height: b - t };
    };
    const walk = n => {
      for (const c of n.childNodes) {
        if (c.nodeType === 3 && c.textContent.trim()) { rg.selectNodeContents(c); for (const r of rg.getClientRects()) rs.push(clipTo(r, n)); }
        else if (c.nodeType === 1 && visible(c)) { if (c.tagName === "svg" || c.tagName === "IMG" || c.tagName === "CANVAS") rs.push(clipTo(c.getBoundingClientRect(), n)); else walk(c); }
      }
    };
    walk(e);
    return rs.filter(r => r.width > 0.5 && r.height > 0.5);
  };
  const parents = new Set(vis.filter(isItem).map(e => e.parentElement));
  for (const p of parents) {
    const kids = [...p.children].filter(k => visible(k) && isItem(k)).map(k => [k, ink(k)]);
    for (let i = 0; i < kids.length; i++)
      for (let j = i + 1; j < kids.length; j++) {
        let hit = null;
        for (const a of kids[i][1])
          for (const b of kids[j][1]) {
            const ix = Math.min(a.right, b.right) - Math.max(a.left, b.left), iy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
            if (ix > 2 && iy > 2) hit = { with: name(kids[i][0]), ix: Math.round(ix), iy: Math.round(iy) };
          }
        if (hit) add("overlap", kids[j][0], hit);
      }
  }
  return out;
}

const b = await chromium.launch({ args: ["--disable-gpu", "--disable-dev-shm-usage"] });
const BASE = new URL("../ui/index.html#", import.meta.url).href;
const issues = [];
const errors = [];
const t0 = Date.now();
for (const W of WIDTHS) {
  const ctx = await b.newContext({ viewport: { width: W, height: 852 }, deviceScaleFactor: 1, isMobile: true, hasTouch: true, locale: "ru-RU" });
  await ctx.addInitScript(h => { window.FOCA_DEMO_HELP = h; }, help);
  await ctx.addInitScript(u => { window.FOCA_DEMO_UI = u; }, ui);
  await ctx.addInitScript(f => { window.FOCA_DEMO_FINDINGS = f; }, findingsCat);
  const p = await ctx.newPage();
  p.on("pageerror", e => errors.push(e.message));
  for (const lang of LANGS)
    for (const fsc of FSS) {
      const cfg = `${lang} ${W} fs${fsc}`;
      await p.goto("about:blank");
      await p.goto(BASE + "/projects");
      await p.waitForFunction(() => window.FOCA && FOCA.cur && document.querySelector(".page"), null, { timeout: 15000 }).catch(() => errors.push("READY timeout " + cfg));
      await p.evaluate(async ([l, f]) => {
        localStorage.setItem("foca-welcomed", "1");
        await FOCA.i18n.setLang(l);
        document.documentElement.style.setProperty("--fs", f);
        FOCA.setTheme("dark");
        window.__setInsets && window.__setInsets(32, 20, 0, 0);
      }, [lang, fsc]);
      for (const r of ROUTES) {
        await p.evaluate(r => FOCA.go(r), r).catch(e => errors.push(`${cfg} ${r}: ${e.message}`));
        await p.waitForTimeout(250);
        const found = await p.evaluate(detect).catch(e => { errors.push(`${cfg} ${r}: ${e.message}`); return []; });
        if (lang !== "ru" && W === WIDTHS[0] && fsc === FSS[0]) found.push(...(await p.evaluate(detectRussian).catch(() => [])));
        const cur = await p.evaluate(() => (FOCA.cur && FOCA.cur.path) || location.hash.slice(1));
        for (const it of found) issues.push({ ...it, route: r, at: cur, cfg, lang, W, fs: fsc });
      }
    }
  await ctx.close();
}
await b.close();

// Group the same defect across configurations; apply the allow-list.
const groups = new Map();
for (const it of issues) {
  const allowed = ALLOW.find(a => a.kind === it.kind && a.sel.test(it.sel) && (!a.route || a.route.test(it.route)));
  const key = [it.kind, it.route, it.sel].join("|");
  if (!groups.has(key)) groups.set(key, { kind: it.kind, route: it.route, sel: it.sel, text: it.text, allowed: allowed ? allowed.why : null, cfgs: [], data: it.data, n: 0 });
  const g = groups.get(key);
  g.n++;
  if (!g.cfgs.includes(it.cfg)) g.cfgs.push(it.cfg);
}
const all = [...groups.values()];
const INFO = new Set(["ellipsis-no-title", "input-ellipsis", "ru-text"]);
// Russian text: known cases (demo-only texts, developer log lines) live in qa/layout-sweep-ru.txt; a new one fails.
// Refresh the list after a review with --update-ru.
const RU_FILE = path.join(ROOT, "qa/layout-sweep-ru.txt");
const ruKey = g => `${g.route} | ${g.text.slice(0, 70)}`;
const ruKnown = new Set(fs.existsSync(RU_FILE) ? fs.readFileSync(RU_FILE, "utf8").split("\n").filter(l => l && !l.startsWith("#")) : []);
const ruAll = [...new Set(all.filter(g => g.kind === "ru-text").map(ruKey))].sort();
if (process.argv.includes("--update-ru"))
  fs.writeFileSync(RU_FILE, "# Known Russian text on EN/UK screens (qa/layout-sweep.mjs --update-ru): demo-only data and developer logs.\n" + ruAll.join("\n") + "\n");
const ruNew = process.argv.includes("--update-ru") ? [] : ruAll.filter(k => !ruKnown.has(k));
for (const k of ruNew) console.log("NEW ru-text: " + k);
const real = [...all.filter(g => !g.allowed && !INFO.has(g.kind)), ...ruNew];
const count = k => all.filter(g => g.kind === k && !g.allowed).length;
const kinds = ["page-overflow", "clipped-text", "text-spill", "input-text", "cut", "spill", "overlap", "ellipsis-no-title", "input-ellipsis", "ru-text"];
const summary = Object.fromEntries(kinds.map(k => [k, count(k)]));
fs.writeFileSync(path.join(OUT, "report.json"), JSON.stringify({ routes: ROUTES.length, langs: LANGS, widths: WIDTHS, fs: FSS, summary, errors, issues: all }, null, 1));
const md = [`# Layout sweep`, ``, `Routes ${ROUTES.length} × ${LANGS.join("/")} × ${WIDTHS.join("/")} px × fs ${FSS.join("/")} (dark), ${Math.round((Date.now() - t0) / 1000)} s.`, ``, `| kind | count |`, `|---|---|`, ...kinds.map(k => `| ${k} | ${summary[k]} |`), ``];
for (const g of all.sort((a, b) => a.route.localeCompare(b.route) || a.kind.localeCompare(b.kind)))
  md.push(`- ${g.allowed ? "(allowed) " : INFO.has(g.kind) ? "(info) " : ""}**${g.kind}** \`${g.route}\` \`${g.sel}\` «${g.text}» ${JSON.stringify(g.data)}, ${g.cfgs.length} cfg: ${g.cfgs.slice(0, 4).join(", ")}`);
if (errors.length) md.push("", "## Errors", ...errors.slice(0, 50).map(e => "- " + e));
fs.writeFileSync(path.join(OUT, "report.md"), md.join("\n") + "\n");
console.log(`layout sweep: ${ROUTES.length} routes × ${LANGS.length * WIDTHS.length * FSS.length} configs; ${kinds.map(k => `${k} ${summary[k]}`).join(", ")}; errors ${errors.length}`);
console.log(`report: ${path.relative(ROOT, path.join(OUT, "report.md"))}`);
console.log(real.length || errors.length ? `LAYOUT FAIL: ${real.length} issue(s), ${errors.length} error(s)` : "LAYOUT OK");
process.exit(real.length || errors.length ? 1 : 0);
