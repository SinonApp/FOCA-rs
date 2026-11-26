// The UI renders finding texts with ui/js/ftext.js, a port of the report translator (foca-report src/ftext.rs).
// Both read the same vectors: every catalog template filled with sample values, in English and Ukrainian.
//   node qa/check-ftext.mjs            # check ui/js/ftext.js against the vectors
//   node qa/check-ftext.mjs --write    # regenerate the vectors after a catalog change
// The Rust side checks the same file in `ftext::tests::shared_vectors_match`.
import fs from "fs";
import path from "path";
import vm from "vm";
import { fileURLToPath } from "url";
import { demoFindings } from "./demo-locales.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const FILE = path.join(ROOT, "crates/foca-report/tests/fixtures/ftext_vectors.json");
const ctx = { console, Map, Set, JSON, Object, Array, String, Number, RegExp };
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(ROOT, "ui/js/ftext.js"), "utf8"), ctx, { filename: "ftext.js" });
const FT = ctx.FOCA.ftext;
const cats = demoFindings(ROOT);

const sample = pat => {
  let k = 0;
  return pat.replace(/\{(n|w)?\}/g, (_, t) => (t === "n" ? String(2 + (k++ % 4) * 3) : t === "w" ? "документов" : `X${++k}`));
};
const firstRule = spec =>
  spec
    .split(",")
    .map(s => s.trim())
    .find(s => s && s !== "*" && !s.endsWith("*")) ||
  spec.split(",")[0].trim().replace(/\*$/, "x");

const vectors = [];
const ru = JSON.parse(fs.readFileSync(path.join(ROOT, "locales/ru/findings.json"), "utf8")).catalog;
for (const lang of ["en", "uk"]) {
  FT.setCatalog(lang, cats[lang]);
  for (const e of ru) {
    const rule = firstRule(e.rules);
    const text = sample(e.pattern);
    vectors.push({ lang, rule, text, out: FT.translate(text, rule) });
  }
  // Multi-line text is translated line by line; unknown text stays.
  vectors.push({ lang, rule: "eol-software", text: "Сигнатура: Word 2010\nДокументов: 2", out: null });
  vectors.push({ lang, rule: "unknown-rule", text: "Что-то новое", out: null });
}
for (const v of vectors)
  if (v.out === null) {
    FT.setCatalog(v.lang, cats[v.lang]);
    v.out = FT.translate(v.text, v.rule);
  }

if (process.argv.includes("--write")) {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(vectors, null, 1) + "\n");
  console.log(`wrote ${vectors.length} vectors`);
  process.exit(0);
}
const saved = JSON.parse(fs.readFileSync(FILE, "utf8"));
const key = v => `${v.lang}|${v.rule}|${v.text}`;
const want = new Map(saved.map(v => [key(v), v.out]));
let bad = 0;
for (const v of vectors) {
  if (!want.has(key(v))) {
    bad++;
    console.log(`FAIL missing vector (run --write): ${key(v)}`);
  } else if (want.get(key(v)) !== v.out) {
    bad++;
    console.log(`FAIL ${key(v)}\n  want ${want.get(key(v))}\n  got  ${v.out}`);
  }
}
if (saved.length !== vectors.length) {
  bad++;
  console.log(`FAIL ${saved.length} saved vectors, ${vectors.length} generated (run --write)`);
}
console.log(bad ? `FAILED: ${bad} of ${vectors.length}` : `ALL GREEN: ${vectors.length} finding text vectors`);
process.exit(bad ? 1 : 0);
