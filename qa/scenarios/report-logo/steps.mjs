// Custom report logo (demo backend): choose a picture in the report builder through the file
// chooser, the WebView downscales it to 512 px and the thumbnail shows name and size; the preview
// header and title page show the image; an SVG is refused; the logo survives a reload; "Remove"
// brings the initials back.
// qa/shoot.sh --routes none --out /tmp/x --steps $PWD/qa/scenarios/report-logo/steps.mjs [--w 360 --theme light --fs 2]
import zlib from "zlib";

// A real RGB PNG (stripes), so the WebView can decode and redraw it.
function png(w, h) {
  const crcT = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = b => {
    let c = 0xffffffff;
    for (const x of b) c = crcT[(c ^ x) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (t, d) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(d.length);
    const td = Buffer.concat([Buffer.from(t), d]);
    const c = Buffer.alloc(4);
    c.writeUInt32BE(crc(td));
    return Buffer.concat([len, td, c]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr.set([8, 2, 0, 0, 0], 8);
  const rows = [];
  for (let y = 0; y < h; y++) {
    const r = Buffer.alloc(1 + w * 3);
    for (let x = 0; x < w; x++) r.set(x % 120 < 60 ? [15, 76, 129] : [245, 158, 11], 1 + x * 3);
    rows.push(r);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(Buffer.concat(rows))),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

export default async (page, { W, fsc, theme, out, prep, go }) => {
  let fails = 0,
    oks = 0;
  const ok = (name, cond, data) => {
    if (cond) oks++;
    else fails++;
    console.log(`${cond ? "OK  " : "FAIL"} ${name}${!cond && data !== undefined ? " - " + JSON.stringify(data) : ""}`);
  };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => {
    await wait(300);
    await page.screenshot({ path: `${out}/report-logo_${n}_${tag}.png` });
  };
  const nav = async r => {
    await ev(r => FOCA.go(r), r);
    await wait(500);
  };
  const choose = async (file, act = "rp-logo-pick") => {
    const [fc] = await Promise.all([
      page.waitForEvent("filechooser", { timeout: 5000 }),
      ev(a => FOCA.actions[a](), act),
    ]);
    await fc.setFiles(file);
    await wait(900);
  };
  const row = () =>
    ev(() => {
      const r = document.querySelector(".rp-logorow");
      if (!r) return null;
      r.scrollIntoView({ block: "center" });
      const img = r.querySelector(".rp-logo img");
      return {
        img: !!img && img.naturalWidth > 0,
        initials: (r.querySelector(".rp-logo span") || {}).textContent || "",
        sub: r.querySelector(".s").textContent,
        acts: [...r.querySelectorAll("[data-act]")].map(b => b.dataset.act),
      };
    });

  await go("/projects");
  await ev(() => FOCA_DEMO_BACKEND.invokeSync("report_logo_clear", {}));
  await go("/p/report-new");
  await prep();
  await wait(400);
  let r = await row();
  ok("builder: no logo yet, Choose only", r && !r.img && r.acts.join() === "rp-logo-pick", r);
  ok(
    "builder: logo option on by default",
    await ev(() => !!document.querySelector('[data-act="rp-logo"][aria-checked="true"]')),
  );

  // a 900×300 PNG is downscaled to 512×171 before it is saved
  await choose({ name: "acme-logo.png", mimeType: "image/png", buffer: png(900, 300) });
  r = await row();
  ok("thumbnail is the picked image", r && r.img, r);
  ok("thumbnail line: name and downscaled size", r && /acme-logo\.png · 512×171 · /.test(r.sub), r && r.sub);
  ok("Replace and Remove offered", r && r.acts.includes("rp-logo-pick") && r.acts.includes("rp-logo-del"), r);
  const saved = await ev(() => FOCA_DEMO_BACKEND.invokeSync("report_logo_get", {}).logo);
  ok("saved in the store", saved && saved.w === 512 && saved.h === 171 && /^data:image\/png;base64,/.test(saved.data), saved && { w: saved.w, h: saved.h });
  await shot("1_builder");

  // an SVG is refused, the logo stays
  await choose({ name: "evil.svg", mimeType: "image/svg+xml", buffer: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>') });
  const snack = await ev(() => (document.querySelector("#snack") || {}).textContent || "");
  ok("SVG refused with a message", /PNG, JPEG/.test(snack), snack);
  r = await row();
  ok("SVG left the logo as it was", r && r.img && /acme-logo\.png/.test(r.sub), r);
  // a file over 2 MB is refused before reading
  await choose({ name: "huge.png", mimeType: "image/png", buffer: Buffer.concat([png(10, 10), Buffer.alloc(2 * 1024 * 1024)]) });
  ok("file over 2 MB refused", /2/.test(await ev(() => (document.querySelector("#snack") || {}).textContent || "")));
  await wait(400);

  // the logo survives a reload (store, not just memory)
  await go("/p/report-new");
  await prep();
  await wait(600);
  r = await row();
  ok("logo kept after reload", r && r.img && /acme-logo\.png/.test(r.sub), r);

  // preview: the image in every sheet header and on the title page
  await ev(() => FOCA.actions["rp-preview"]());
  await wait(900);
  const pv = await ev(() => ({
    sheets: document.querySelectorAll(".rp-paper").length,
    heads: [...document.querySelectorAll(".rp-ph img.rp-plogo")].filter(i => i.naturalWidth > 0).length,
    title: !!document.querySelector(".rp-title img.rp-tlogo"),
    initials: document.querySelectorAll("i.rp-plogo").length,
  }));
  ok("preview: logo image in every header", pv.sheets > 1 && pv.heads === pv.sheets, pv);
  ok("preview: logo on the title page, no initials", pv.title && pv.initials === 0, pv);
  await shot("2_preview");

  // the logo option off: no logo anywhere in the preview
  await nav("/p/report-new");
  await ev(() => FOCA.actions["rp-logo"]());
  await wait(300);
  await ev(() => FOCA.actions["rp-preview"]());
  await wait(700);
  ok("option off: no logo in the preview", await ev(() => !document.querySelector(".rp-plogo, .rp-tlogo")));
  await nav("/p/report-new");
  await ev(() => FOCA.actions["rp-logo"]());
  await wait(300);

  // remove: initials come back in the builder and in the preview
  await page.fill("#rp-company", "Cyber Audit LLC");
  await wait(300);
  await ev(() => FOCA.actions["rp-logo-del"]());
  await wait(500);
  r = await row();
  ok("removed: initials thumbnail, Choose only", r && !r.img && r.initials === "CA" && r.acts.join() === "rp-logo-pick", r);
  ok("removed from the store", (await ev(() => FOCA_DEMO_BACKEND.invokeSync("report_logo_get", {}).logo)) === null);
  await shot("3_removed");
  await ev(() => FOCA.actions["rp-preview"]());
  await wait(700);
  const pv2 = await ev(() => ({
    img: document.querySelectorAll("img.rp-plogo, img.rp-tlogo").length,
    initials: document.querySelectorAll("i.rp-plogo").length,
  }));
  ok("preview after removal: initials fallback", pv2.img === 0 && pv2.initials > 0, pv2);
  // leave the demo executor as it was
  await nav("/p/report-new");
  await page.fill("#rp-company", "");
  await wait(600);
  console.log(`${oks} OK, ${fails} FAIL`);
};
