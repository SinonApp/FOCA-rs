// PDF check of the report logo: the HTML report with a logo (written by the foca-report logo
// test) is printed to PDF in Chromium, the same engine as the Android WebView print path, and the
// PDF must hold one more image XObject than the same report printed without the logo.
// Run: bash qa/scenarios/report-logo/pdf.sh
import fs from "fs";

const { chromium } = (await import(process.env.PW_CORE || "playwright-core")).default;
const [withLogo] = process.argv.slice(2);
const html = fs.readFileSync(withLogo, "utf8");
// the same report without the logo image: drop the <img> of the cover
const without = html.replace(/<img src="data:image\/[a-z]+;base64,[^"]*" alt="">/g, "");
const images = buf => (buf.toString("latin1").match(/\/Subtype\s*\/Image/g) || []).length;
const browser = await chromium.launch();
const page = await browser.newPage();
const pdf = async h => {
  await page.setContent(h, { waitUntil: "load" });
  return page.pdf({ format: "A4", printBackground: true });
};
const a = images(await pdf(html));
const b = images(await pdf(without));
await browser.close();
const ok = html !== without && a === b + 1;
console.log(`${ok ? "OK  " : "FAIL"} PDF image objects: with logo ${a}, without ${b}`);
console.log(`${ok ? 1 : 0} OK, ${ok ? 0 : 1} FAIL`);
process.exit(ok ? 0 : 1);
