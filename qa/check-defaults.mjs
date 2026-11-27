// Every default of a manual numeric setting must sit inside its own recommended range and must
// never trigger its own warning (ui/js/limits.js). Defaults come from the core
// (crates/foca-store/src/settings.rs), the crawl screen (ui/screens/crawl.js DEF), the demo
// backend settings and the launch wizard; the copies must also agree with the core.
// node qa/check-defaults.mjs
import fs from "fs";
import vm from "vm";

const root = new URL("..", import.meta.url).pathname;
const read = p => fs.readFileSync(root + p, "utf8");
let fails = 0;
const log = (ok, name, data) => {
  if (!ok) fails++;
  console.log(`${ok ? "OK  " : "FAIL"} ${name}${ok ? "" : " " + JSON.stringify(data ?? "")}`);
};

// limits.js in a bare context
const ctx = { window: { FOCA: {} } };
vm.createContext(ctx);
vm.runInContext(read("ui/js/limits.js"), ctx);
const LIM = ctx.window.FOCA.limits;

// Core defaults: the json!({...}) literal inside `fn defaults()`.
const rs = read("crates/foca-store/src/settings.rs");
const body = rs.slice(rs.indexOf("pub(crate) fn defaults()"));
const start = body.indexOf("json!(", body.indexOf("for k in KEY_SERVICES") + 80) + 6;
let depth = 0,
  end = start;
for (let i = start; i < body.length; i++) {
  if (body[i] === "{") depth++;
  else if (body[i] === "}" && --depth === 0) {
    end = i + 1;
    break;
  }
}
const core = JSON.parse(body.slice(start, end).replace(/"keys":\s*keys/, '"keys": {}'));
const at = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);

// Copies of the defaults outside the core.
const crawlJs = read("ui/screens/crawl.js");
const def = crawlJs.slice(crawlJs.indexOf("const DEF = {"), crawlJs.indexOf("};", crawlJs.indexOf("const DEF = {")));
const crawlDef = Object.fromEntries([...def.matchAll(/(\w+):\s*(\d+)/g)].map(m => [m[1], +m[2]]));
const demo = read("ui/js/demo-backend.js");
const launch = read("ui/screens/launch.js");
const wiz = (name, fb) => {
  const m = launch.match(new RegExp(`${name}: wiz\\.${name} \\?\\? (\\d+)`));
  return m ? +m[1] : fb;
};
const extra = { "scan.max_docs": wiz("maxDocs"), "scan.max_size_mb": wiz("maxSize") };

const check = (src, key, v) => {
  const L = LIM.get(key);
  if (v == null) return log(false, `${src}: ${key} has a default`, v);
  const w = LIM.warning(key, v);
  const inRec = !L.rec || (v >= L.rec[0] && v <= L.rec[1]);
  log(!w && inRec && v >= L.min, `${src}: ${key} default ${v} is inside ${L.rec ? L.rec.join("-") : "-"} with no warning`, {
    v,
    rec: L.rec,
    warning: w,
  });
};

for (const key of Object.keys(LIM.all)) {
  if (key in extra) check("launch wizard", key, extra[key]);
  // Legacy per-scan key: the wizard starts from crawl.max_depth.
  else if (key === "scan.crawl_depth") check("launch wizard", key, core.crawl.max_depth);
  else check("core", key, at(core, key));
}
for (const [k, v] of Object.entries(crawlDef)) {
  log(core.crawl[k] === v, `crawl.js DEF.${k} = core crawl.${k} (${v})`, { ui: v, core: core.crawl[k] });
}
// Demo backend crawl section mirrors the core.
const dm = demo.match(/crawl:\s*\{([^}]*)\}/);
if (dm) {
  for (const m of dm[1].matchAll(/(\w+):\s*(\d+)/g)) {
    if (core.crawl[m[1]] != null)
      log(core.crawl[m[1]] === +m[2], `demo crawl.${m[1]} = core (${m[2]})`, { demo: +m[2], core: core.crawl[m[1]] });
  }
} else log(false, "demo backend has a crawl settings section");

console.log(fails ? `${fails} failed` : "0 failed");
process.exit(fails ? 1 : 0);
