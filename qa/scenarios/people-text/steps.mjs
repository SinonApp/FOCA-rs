// People from document text: Phones segment (full numbers) and a person card with position, unit,
// signatory mark and contacts written next to the name. Fails on horizontal overflow.
export default async (page, ctx) => {
  const log = [];
  try {
    await run(page, ctx, log);
  } finally {
    console.error(JSON.stringify(log));
  }
};
const run = async (page, { out, W, prep }, log) => {
  const shot = async n => {
    await page.waitForTimeout(350);
    await page.screenshot({ path: `${out}/step_${n}_${W}.png` });
  };
  const ev = (f, a) => page.evaluate(f, a);
  const check = (name, ok, info = "") => {
    log.push({ name, ok, info });
    console.log(`${ok ? "OK  " : "FAIL"} ${name}${info ? ` (${info})` : ""}`);
  };
  const open = async r => {
    await page.goto("about:blank");
    await page.goto(new URL("../../../ui/index.html#", import.meta.url).href + r);
    await page.waitForTimeout(250);
    await prep();
    await page.waitForTimeout(400);
  };
  const overflow = () =>
    ev(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

  await open("/p/data/phones");
  const phones = await ev(() => [...document.querySelectorAll(".list .mono")].map(e => e.textContent));
  check(
    "phones segment lists full numbers",
    phones.length > 0 && phones.every(v => !v.includes("•") && /\d{6,}/.test(v.replace(/\D/g, ""))),
    String(phones.length),
  );
  check("phones segment has no horizontal overflow", (await overflow()) <= 1);
  await shot("01_phones");

  const login = await ev(() => (FOCA.db.people.find(p => p.title && p.unit) || {}).login || "");
  check("a text person has a title and unit", !!login);
  await open(`/p/entity/person/${encodeURIComponent(login)}`);
  const txt = await ev(() => document.querySelector("#page, main, body").innerText);
  const t = await ev(l => FOCA.db.people.find(p => p.login === l), login);
  check("person card shows the position", txt.includes(t.title));
  check("person card shows the unit", txt.includes(t.unit));
  check(
    "person card shows the full phone",
    (t.phones || []).every(v => txt.includes(v)),
  );
  check("person card has no horizontal overflow", (await overflow()) <= 1);
  await shot("02_person");
};
