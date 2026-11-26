// Static i18n checks of the UI scripts: node qa/check-i18n.mjs
// - no F.t(...) is evaluated at script load time (module-level constants, route titles, menu labels): the
//   dictionary arrives after the scripts ran on Android and the language can change in the app, so such
//   texts freeze in the fallback language. Wrap them in a function instead.
// - every literal key of F.t("key", …) exists in the merged ru/en/uk dictionaries (locales/<lang>/ui.json +
//   locales/<lang>/ui/*.json). Dynamic keys (template literals such as `sev.${id}`) must have at least one
//   dictionary key with their static prefix; keys held in variables are not checked.
import fs from "fs";
import { fileURLToPath } from "url";
import * as acorn from "acorn";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const scripts = ["ui/js", "ui/screens"].flatMap(d =>
  fs
    .readdirSync(ROOT + d)
    .filter(f => f.endsWith(".js") && f !== "demo-backend.js")
    .map(f => `${d}/${f}`),
);
let fails = 0;
const fail = msg => {
  fails++;
  console.log("FAIL " + msg);
};

// Translation calls: F.t / FOCA.t, plural templates F.tp and the local fallbacks tr/tx used where core.js may be absent.
const isTr = n =>
  n.type === "CallExpression" &&
  ((n.callee.type === "MemberExpression" &&
    !n.callee.computed &&
    ["t", "tp"].includes(n.callee.property.name) &&
    ["F", "FOCA"].includes(n.callee.object.name)) ||
    (n.callee.type === "Identifier" && ["tr", "tx"].includes(n.callee.name)));

const parsed = {};
for (const f of scripts) {
  const src = fs.readFileSync(ROOT + f, "utf8");
  parsed[f] = acorn.parse(src, { ecmaVersion: "latest", sourceType: "script", locations: true });
}

// Walks the AST; `fnDepth` counts enclosing functions (the file's outer IIFE is depth 1 = load time).
const walk = (n, fnDepth, visit) => {
  if (!n || typeof n.type !== "string") return;
  const d = /Function/.test(n.type) ? fnDepth + 1 : fnDepth;
  visit(n, d);
  for (const k of Object.keys(n)) {
    if (k === "loc") continue;
    const v = n[k];
    if (Array.isArray(v)) v.forEach(x => walk(x, d, visit));
    else if (v && typeof v.type === "string") walk(v, d, visit);
  }
};

let loadTime = 0;
for (const f of scripts)
  walk(parsed[f], 0, (n, d) => {
    if (d <= 1 && isTr(n)) {
      loadTime++;
      fail(`${f}:${n.loc.start.line} translation evaluated at script load (wrap it in a function)`);
    }
  });
console.log(`${loadTime ? "FAIL" : "ok  "} load-time translations: ${loadTime}`);

// ---- keys used in the UI exist in every language
const LANGS = ["ru", "en", "uk"];
const dict = {};
for (const l of LANGS) {
  dict[l] = {};
  const files = [`locales/${l}/ui.json`].concat(
    fs
      .readdirSync(ROOT + `locales/${l}/ui`)
      .filter(f => f.endsWith(".json"))
      .map(f => `locales/${l}/ui/${f}`),
  );
  for (const f of files) Object.assign(dict[l], JSON.parse(fs.readFileSync(ROOT + f, "utf8")));
}
const used = new Map(); // key -> first "file:line"
const prefixes = new Map(); // static prefix of a dynamic key -> first "file:line"
for (const f of scripts)
  walk(parsed[f], 0, n => {
    if (!isTr(n) || !n.arguments.length) return;
    const a = n.arguments[0],
      at = `${f}:${n.loc.start.line}`;
    if (a.type === "Literal" && typeof a.value === "string") {
      if (!used.has(a.value)) used.set(a.value, at);
    } else if (a.type === "TemplateLiteral") {
      const pre = a.quasis[0].value.cooked;
      if (a.expressions.length === 0) {
        if (!used.has(pre)) used.set(pre, at);
      } else if (pre && !prefixes.has(pre)) prefixes.set(pre, at); // `${key}.l` in table helpers: fully dynamic.
    }
  });
let missing = 0;
for (const [k, at] of used)
  for (const l of LANGS)
    if (!(k in dict[l])) {
      missing++;
      fail(`${at} key "${k}" missing in ${l}`);
    }
for (const [pre, at] of prefixes)
  for (const l of LANGS)
    if (!Object.keys(dict[l]).some(k => k.startsWith(pre))) {
      missing++;
      fail(`${at} dynamic key prefix "${pre}" matches no ${l} key`);
    }
console.log(
  `${missing ? "FAIL" : "ok  "} keys: ${used.size} literal, ${prefixes.size} dynamic prefixes, ${missing} missing`,
);

// ---- core message codes: every `{ code: "…" }` the demo backend sends in `*_msg` exists in core.json
// of every language, and the three core.json files carry the same keys and placeholders.
const demoSrc = fs.readFileSync(ROOT + "ui/js/demo-backend.js", "utf8");
const codes = new Set(
  [
    ...demoSrc.matchAll(/_msg:\s*\{[^}]*?code:\s*"([a-z0-9_.-]+)"/g),
    ...demoSrc.matchAll(/\{\s*code:\s*"(src\.[a-z0-9_.-]+)"/g),
  ].map(m => m[1]),
);
let coreBad = 0;
for (const c of codes)
  for (const l of LANGS)
    if (!(`core.${c}` in dict[l])) {
      coreBad++;
      fail(`demo-backend.js core code "${c}" missing in locales/${l}/ui/core.json`);
    }
const ph = s =>
  [...String(s).matchAll(/\{([a-z_]+)\}/g)]
    .map(m => m[1])
    .sort()
    .join(",");
const coreRu = JSON.parse(fs.readFileSync(ROOT + "locales/ru/ui/core.json", "utf8"));
for (const l of ["en", "uk"]) {
  const other = JSON.parse(fs.readFileSync(ROOT + `locales/${l}/ui/core.json`, "utf8"));
  for (const k of new Set([...Object.keys(coreRu), ...Object.keys(other)]))
    if (!(k in coreRu) || !(k in other) || ph(coreRu[k]) !== ph(other[k])) {
      coreBad++;
      fail(`core.json ${l}: key "${k}" missing or placeholders differ from ru`);
    }
}
console.log(
  `${coreBad ? "FAIL" : "ok  "} core messages: ${codes.size} demo codes, ${Object.keys(coreRu).length} keys`,
);

console.log(fails ? `FAILED: ${fails} problem(s)` : "ALL GREEN: i18n static checks");
process.exit(fails ? 1 : 0);
