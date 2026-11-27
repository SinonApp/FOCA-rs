// Release checks that need no browser:
// - the in-app "What's new" note (ui/screens/settings.js CHANGES[0]) describes the version in
//   src-tauri/tauri.conf.json, and the About fallback version matches it;
// - every note line has a text in ru, uk and en.
// node qa/check-release.mjs
import fs from "fs";

const root = new URL("..", import.meta.url).pathname;
const read = p => fs.readFileSync(root + p, "utf8");
let fails = 0;
const log = (ok, name, data) => {
  if (!ok) fails++;
  console.log(`${ok ? "OK  " : "FAIL"} ${name}${ok ? "" : " " + JSON.stringify(data ?? "")}`);
};

const appV = JSON.parse(read("src-tauri/tauri.conf.json")).version;
const js = read("ui/screens/settings.js");
const head = js.slice(js.indexOf("const CHANGES = ["));
const m = head.match(/\[\s*"([^"]+)",\s*"(\d{4}-\d\d-\d\d)",\s*\[([\s\S]*?)\]\s*,?\s*\]/);
const noteV = m && m[1];
const lines = m ? [...m[3].matchAll(/"((?:[^"\\]|\\.)*)"/g)].length : 0;
log(noteV === appV, `what's new note version ${noteV} = tauri.conf.json ${appV}`, { noteV, appV });
const fb = (js.match(/const APP_VERSION_FALLBACK = "([^"]+)"/) || [])[1];
log(fb === appV, `About fallback version ${fb} = ${appV}`, { fb, appV });
log(lines > 0, `note has lines (${lines})`, lines);
const key = String(noteV).replace(/[.-]/g, "_");
for (const lang of ["ru", "uk", "en"]) {
  const d = JSON.parse(read(`locales/${lang}/ui/settings.json`));
  const miss = [];
  for (let i = 0; i < lines; i++) if (!d[`settings.chg_${key}_${i}`]) miss.push(i);
  if (d[`settings.chg_${key}_${lines}`]) miss.push(`extra ${lines}`);
  log(!miss.length, `${lang}: note lines settings.chg_${key}_0..${lines - 1}`, miss);
}
console.log(fails ? `${fails} failed` : "0 failed");
process.exit(fails ? 1 : 0);
