// Demo: analytics, web audit and document hygiene. Layered graph (layer chips, cluster expand/collapse,
// zoom, "link chain" from a node and from a critical finding), internal network map (roles, users, sources),
// timeline year lanes and the 7×24 heat map with working hours, org chart with evidence, KEV / anomaly /
// lineage blocks in findings and document cards, web audit in the host card, preflight hygiene (set grade,
// steps, options, before/after with the field diff), the share target screen (shared file → grade → clean →
// signature warning → share a clean copy), help articles; no horizontal overflow and tap targets ≥ 44 px.
// qa/shoot.sh --routes /p/overview --out $PWD/qa/out/ins --w 393 --steps $PWD/qa/scenarios/insights-1-4/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(250); await page.screenshot({ path: `${out}/ins_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const wide = () => ev(() => {
    const pg = FOCA.page() || document.body;
    const out = [`doc ${document.documentElement.scrollWidth}/${innerWidth} page ${pg.scrollWidth}/${pg.clientWidth}`];
    for (const e of pg.querySelectorAll("*")) {
      const r = e.getBoundingClientRect();
      if ((r.right > innerWidth + 1 || r.left < -1) && !e.closest(".ins-gwrap,.chips,.ins-layers")) out.push(`${e.tagName}.${e.className} ${Math.round(r.left)}..${Math.round(r.right)}`);
      if (out.length > 5) break;
    }
    for (const e of pg.querySelectorAll("*")) if (e.scrollWidth > pg.clientWidth && out.length < 10) out.push(`sw ${e.tagName}.${e.className} ${e.scrollWidth} ${getComputedStyle(e).overflowX}`);
    return out;
  });
  const noOvf = async n => { const v = await overflow(); console.log(`STEP ${n.replace(/\s+/g, "_")} overflow [${v > 1 ? v : 0}]`); ok(`${n}: no horizontal overflow`, v <= 1, v > 1 ? [v, await wide()] : v); };
  const scrollTo = sel => ev(s => { const el = document.querySelector(s); if (el) el.scrollIntoView({ block: "start" }); return !!el; }, sel);
  const clickAct = act => ev(a => { const b = document.querySelector(`[data-act="${a}"]`); if (b) b.dispatchEvent(new MouseEvent("click", { bubbles: true })); return !!b; }, act);
  const sheetTxt = () => ev(() => (document.querySelector(".sheet.show") || {}).textContent || "");
  const closeSheet = async () => { await ev(() => FOCA.closeSheet && FOCA.closeSheet()); await wait(250); };
  // Tap targets of the visible interactive elements inside the page (same rules as regression-round2/a11y).
  const smallTargets = () => ev(() => {
    const vis = e => { const s = getComputedStyle(e); if (s.visibility === "hidden" || s.display === "none" || +s.opacity === 0) return false; const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && !e.closest('[hidden],[aria-hidden="true"]') && !(e.closest("details:not([open])") && !e.closest("summary")); };
    const els = [...(FOCA.page() || document).querySelectorAll("button,[data-act],[role=button],[role=link],[role=radio],[role=checkbox],[role=switch],input,textarea,summary")].filter(vis);
    const small = [];
    for (const e of els) {
      if (e.parentElement && e.parentElement.closest("[data-act],button") && !e.matches("button,input,textarea")) continue;
      const r = e.getBoundingClientRect(); let w = r.width, h = r.height;
      for (const ps of ["::before", "::after"]) { const s = getComputedStyle(e, ps); if (s.content !== "none" && s.position === "absolute") { const it = parseFloat(s.top), il = parseFloat(s.left); if (it < 0) h = Math.max(h, r.height - 2 * it); if (il < 0) w = Math.max(w, r.width - 2 * il); } }
      const host = e.closest("label, .row.tap, .checkrow, .srow"); if (host && host !== e) { const hr = host.getBoundingClientRect(); w = Math.max(w, hr.width); h = Math.max(h, hr.height); }
      if ((w < 44 || h < 44) && !e.matches("textarea")) small.push([e.dataset.act || e.tagName, Math.round(w), Math.round(h)]);
    }
    return small;
  });
  const targets = async n => { const s = await smallTargets(); ok(`${n}: tap targets ≥ 44 px`, !s.length, s.slice(0, 6)); };
  const errs = []; page.on("pageerror", e => errs.push(e.message));
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(300);

    // ---------- overview: "infrastructure picture" links ----------
    await go("/p/overview"); await wait(300);
    let t = await txt();
    ok("overview: links to graph, network map, org chart and timeline", /Картина инфраструктуры/.test(t) && ["/p/graph", "/p/netmap", "/p/timeline"].every(p => t && true) && (await ev(() => ["go:/p/graph", "go:/p/netmap", "go:/p/timeline"].every(a => !!document.querySelector(`[data-act="${a}"]`)))), t.slice(0, 120));

    // ---------- graph: layers, clusters, zoom ----------
    await go("/p/graph"); await wait(400);
    t = await txt();
    ok("graph: five layer chips with counts", (await ev(() => document.querySelectorAll(".ins-lchip").length)) === 5 && /Люди\s*12/.test(t) && /PKI\/Домены/.test(t), t.slice(0, 160));
    const g0 = await ev(() => ({ n: document.querySelectorAll(".ins-n").length, grp: document.querySelectorAll(".ins-n.grp").length, cols: [...document.querySelectorAll(".ins-col")].map(x => x.textContent) }));
    ok("graph: layered columns and at least one cluster node", g0.n > 10 && g0.grp >= 1 && g0.cols[0] === "Люди", g0);
    ok("graph: critical document nodes highlighted", (await ev(() => document.querySelectorAll(".ins-n.crit").length)) > 0);
    await shot("graph"); await noOvf("graph"); await targets("graph");
    const grpLabel = await ev(() => document.querySelector(".ins-n.grp text").textContent);
    ok("graph: cluster label like «98 документов»", /^\d+ (документ|человек|ПК|сервер|папк|принтер|адрес)/.test(grpLabel), grpLabel);
    const gi = await ev(() => [...document.querySelectorAll(".ins-n")].findIndex(n => n.classList.contains("grp")));
    await clickAct(`ins-node:${gi}`); await wait(500);
    const g1 = await ev(() => ({ n: document.querySelectorAll(".ins-n").length, collapse: !!document.querySelector('[data-act="ins-collapse"]') }));
    ok("graph: tapping a cluster expands it (more nodes, «Свернуть всё»)", g1.n > g0.n && g1.collapse, [g0.n, g1.n]);
    await shot("graph_expanded");
    await clickAct("ins-collapse"); await wait(400);
    ok("graph: «Свернуть всё» restores the clusters", (await ev(() => document.querySelectorAll(".ins-n").length)) === g0.n);
    await clickAct("ins-layer:docs"); await wait(400);
    ok("graph: switching off «Документы» hides the documents column, chip unchecked", !(await ev(() => [...document.querySelectorAll(".ins-col")].some(x => x.textContent === "Документы"))) && (await ev(() => document.querySelector('[data-act="ins-layer:docs"]').getAttribute("aria-checked"))) === "false");
    await clickAct("ins-layer:docs"); await wait(400);
    const w0 = await ev(() => document.querySelector(".ins-svg").getAttribute("width"));
    await clickAct("ins-zoom:1"); await wait(300);
    const w1 = await ev(() => document.querySelector(".ins-svg").getAttribute("width"));
    ok("graph: zoom enlarges the drawing; the card scrolls instead of the page", +w1 > +w0 && (await overflow()) <= 1, [w0, w1]);
    await clickAct("ins-zoom:0"); await wait(300);

    // ---------- link chain ----------
    await clickAct("ins-mode:chain"); await wait(400);
    t = await txt();
    ok("chain mode: hint and the critical findings list", /файл → автор → ПК/.test(t) && (await ev(() => document.querySelectorAll('[data-act^="ins-chain-f:"]').length)) > 0, t.slice(0, 200));
    await shot("chain_mode"); await targets("chain mode");
    const docNode = await ev(() => [...document.querySelectorAll(".ins-n")].findIndex(n => /Договір_постачан/.test(n.textContent)));
    await clickAct(`ins-node:${docNode >= 0 ? docNode : 1}`); await wait(500);
    t = await txt();
    const ch = await ev(() => ({ steps: [...document.querySelectorAll(".ins-chain-step .t")].map(x => x.textContent), via: [...document.querySelectorAll(".ins-chain-via")].map(x => x.textContent), hl: document.querySelectorAll(".ins-n.hl").length }));
    ok("chain: vertical card from the document to infrastructure, edge labels, path highlighted in the graph", /Цепочка связи/.test(t) && ch.steps.length >= 3 && ch.via.length === ch.steps.length - 1 && ch.hl >= 3, ch);
    ok("chain: ends at a server, share or domain", /corp|SRV-|\\\\/.test(ch.steps[ch.steps.length - 1] || ""), ch.steps);
    await scrollTo(".ins-chain"); await shot("chain_card"); await noOvf("chain card"); await targets("chain card");
    await clickAct("ins-chain-close"); await wait(300);
    const cf = await ev(() => document.querySelector('[data-act^="ins-chain-f:"]').dataset.act);
    await clickAct(cf); await wait(500);
    ok("chain: from a critical finding", (await ev(() => document.querySelectorAll(".ins-chain-step").length)) >= 2 || /Путь до инфраструктуры не найден/.test(await txt()), cf);
    await clickAct("ins-mode:graph"); await wait(300);

    // ---------- network map ----------
    await go("/p/netmap"); await wait(400);
    t = await txt();
    ok("netmap: domain → servers by role → workstations → users", /corp/.test(t) && /Файловый сервер/.test(t) && /Принт-сервер/.test(t) && /Терминальный сервер/.test(t) && /База данных/.test(t) && /Рабочие станции/.test(t) && /Олена Коваленко \(o\.kovalenko\)/.test(t), t.slice(0, 300));
    ok("netmap: users are indented under their workstation", (await ev(() => document.querySelectorAll(".ins-nm-r.d2").length)) >= 5);
    await shot("netmap"); await noOvf("netmap"); await targets("netmap");
    const prn = await ev(() => [...document.querySelectorAll(".ins-nm-r")].find(r => /SRV-PRN01/.test(r.textContent)).dataset.act);
    await clickAct(prn); await wait(400);
    t = await sheetTxt();
    ok("netmap: node sheet lists sources with the document, printers and the chain button", /Источники/.test(t) && /принтер|UNC/.test(t) && /Kyocera|Canon/.test(t) && /Цепочка связи/.test(t), t.slice(0, 300));
    await shot("netmap_node");
    await closeSheet();

    // ---------- timeline ----------
    await go("/p/timeline"); await wait(400);
    t = await txt();
    ok("timeline: year lanes documents / software / CT", /Эволюция по годам/.test(t) && (await ev(() => document.querySelectorAll(".ins-ln-r.tap").length)) >= 5 && /Microsoft|LibreOffice|Adobe/.test(t), t.slice(0, 200));
    await scrollTo(".ins-lanes"); await shot("timeline_lanes"); await noOvf("timeline lanes");
    const y = await ev(() => document.querySelector(".ins-ln-r.tap").dataset.act);
    await clickAct(y); await wait(300);
    ok("timeline: year sheet with the programs of that year", /Документы/.test(await sheetTxt()) && /ПО/.test(await sheetTxt()));
    await closeSheet();
    const hm = await ev(() => { const wk = document.querySelector(".ins-wk"); const cells = document.querySelectorAll(".ins-hg i"); return { cells: cells.length, wk: !!wk, abs: wk && getComputedStyle(wk).position, ooh: document.querySelectorAll(".ins-hg i.ooh").length, rows: [...document.querySelectorAll(".ins-hg .v2t-hd")].map(x => x.textContent).join("") }; });
    ok("heat map: 7×24 cells, working hours outlined, out-of-hours cells marked, days in order", hm.cells === 168 && hm.wk && hm.abs === "absolute" && hm.ooh > 0 && hm.rows === "ПнВтСрЧтПтСбВс", hm);
    t = await txt();
    ok("heat map: peak, share out of hours and the time zone", /Пик:/.test(t) && /Вне графика: \d+%/.test(t) && /UTC\+2/.test(t));
    const cellTop = await ev(() => { const c = document.querySelectorAll(".ins-hg i"); return [c[0].getBoundingClientRect().top, c[24].getBoundingClientRect().top, c[167].getBoundingClientRect().top]; });
    ok("heat map: the outline does not shift the grid (row 2 below row 1, last row lowest)", cellTop[1] > cellTop[0] && cellTop[2] > cellTop[1], cellTop);
    await scrollTo(".ins-heat"); await shot("heatmap"); await noOvf("heat map");

    // ---------- org chart ----------
    await go("/p/data/people"); await wait(400);
    t = await txt();
    ok("people: org chart with departments, confidence and members", /Оргструктура/.test(t) && /Финансы и бухгалтерия/.test(t) && /уверенность \d+%/.test(t), t.slice(0, 200));
    await scrollTo(".ins-org"); await shot("org"); await noOvf("org chart"); await targets("org chart");
    await clickAct("ins-org:0"); await wait(300);
    t = await sheetTxt();
    ok("org chart: evidence sheet (source, document) and the analyst caveat", /Обоснование/.test(t) && /локальный путь|сетевая папка|принтер/.test(t) && /гипотеза/.test(t), t.slice(0, 200));
    await closeSheet();

    // ---------- findings: KEV, anomaly, lineage, web audit ----------
    const fid = rule => ev(r => (FOCA.db.findings.find(f => (f.provenance || {}).rule === r) || {}).id, rule);
    const kevLikely = await ev(() => FOCA.db.findings.find(f => (f.provenance || {}).rule === "sw.kev" && f.tags.includes("likely")).id);
    await go(`/p/finding/${kevLikely}`); await wait(300);
    t = await txt();
    ok("KEV finding: «проверьте версию» note, «вероятно» pill, CVE chips, no claim of a confirmed vulnerability", /Проверьте версию/.test(t) && /KEV · вероятно/.test(t) && /CVE-\d{4}-\d+/.test(t) && /не подтверждённая уязвимость/.test(t), t.slice(0, 300));
    await scrollTo(".ins-kev"); await shot("finding_kev"); await noOvf("KEV finding");
    await go(`/p/finding/${await fid("doc.anomaly.date_mismatch")}`); await wait(300);
    t = await txt();
    ok("anomaly finding: explanation, «сигнал для аналитика», link chain button", /Аномалия метаданных/.test(t) && /сигнал для аналитика/.test(t) && (await ev(() => !!document.querySelector('[data-act^="ins-chain:f:"]'))), t.slice(0, 200));
    await ev(() => document.querySelector('[data-act^="ins-chain:f:"]').click()); await wait(500);
    ok("finding: link chain opens as a sheet", (await ev(() => document.querySelectorAll(".sheet.show .ins-chain-step").length)) >= 2);
    await shot("finding_chain"); await closeSheet();
    await go(`/p/finding/${await fid("recon.web.hsts_missing")}`); await wait(300);
    ok("web audit finding: link to the host's web audit", await ev(() => !!document.querySelector('[data-act="go:/p/entity/host/contoso.example"]')));

    // ---------- document card: anomalies, versions ----------
    const anomDoc = await ev(() => FOCA.db.findings.find(f => (f.provenance || {}).rule === "doc.anomaly.date_mismatch").doc);
    await go(`/p/doc/${anomDoc}`); await wait(400);
    t = await txt();
    ok("document card: «Аномалии метаданных» and «Версии и копии»", /Аномалии метаданных/.test(t) && /Даты PDF и XMP расходятся/.test(t) && /Версии и копии/.test(t) && /Исходник для/.test(t), t.slice(0, 200));
    await scrollTo(".ins-kev-d, .list"); await noOvf("document card insights");
    const memo = await ev(() => FOCA.db.docs.find(d => d.name === "Службова_записка_2025_v3.odt").id);
    await go(`/p/doc/${memo}`); await wait(400);
    t = await txt();
    ok("document card: a later version shows «Создан из» and the probable original", /Создан из/.test(t) && /Вероятный оригинал линии/.test(t), t.slice(0, 200));

    // ---------- host card: web audit ----------
    await go("/p/entity/host/contoso.example"); await wait(400);
    t = await txt();
    ok("host card: web audit, level, header issues, CSP domains in/out of scope, source map, API docs", /Веб-аудит/.test(t) && /HSTS/.test(t) && /staging-api\.contoso\.example/.test(t) && /вне скоупа/.test(t) && /app\.3f9c2a\.js\.map/.test(t) && /openapi/.test(t), t.slice(0, 200));
    await scrollTo(".ins-wa-s"); await shot("host_webaudit"); await noOvf("host web audit"); await targets("host web audit");

    // ---------- sources: webaudit ----------
    await go("/settings/sources"); await wait(300);
    ok("sources: web audit listed among site sources", /Веб-аудит: заголовки, CSP, source maps, API/.test(await txt()));

    // ---------- preflight hygiene and before/after ----------
    await ev(() => { FOCA.state.v2.pf = { step: 1, files: [1, 2, 3, 7], cleaned: [] }; FOCA.go("/p/preflight"); }); await wait(600);
    t = await txt();
    ok("preflight: set grade, distribution, frequent issues", /Гигиена набора/.test(t) && (await ev(() => document.querySelectorAll(".hy-dist span").length)) === 6 && /Чаще всего/.test(t), t.slice(0, 200));
    ok("preflight: a grade per file and fix steps (auto / manual)", (await ev(() => document.querySelectorAll(".v2pf-fh .hy-g").length)) === 4 && (await ev(() => document.querySelectorAll(".hy-steps li.auto").length)) > 0 && (await ev(() => document.querySelectorAll(".hy-steps li.man").length)) > 0);
    ok("preflight: three cleaning options", (await ev(() => document.querySelectorAll('[data-act^="hy-opt:"]').length)) === 3);
    await scrollTo(".hy-set"); await shot("preflight_set"); await noOvf("preflight"); await targets("preflight");
    await clickAct("hy-opt:remove_embedded_files"); await wait(200);
    ok("preflight: option toggles", (await ev(() => FOCA.hyg.opts().remove_embedded_files)) === false);
    await clickAct("hy-opt:remove_embedded_files"); await wait(200);
    const photo = await ev(() => FOCA.db.docs.find(d => d.ext === "jpg" && d.gps && !FOCA.db.secrets.some(s => s.doc === d.id)).id);
    await ev(id => { FOCA.state.v2.pf = { step: 1, files: [id], cleaned: [] }; FOCA.go("/p/preflight"); }, photo); await wait(500);
    await clickAct(`v2pf-clean:${photo}`); await wait(600);
    t = await txt();
    ok("clean one file → «До / После»: grades before → after, verdict, diff with было/стало", (await ev(() => FOCA.current())) === "/clean/result" && /было [A-F] → стало A/.test(t) && /0 метаданных · файл валиден/.test(t) && /GPS/.test(t) && /было/.test(t) && /стало/.test(t), t.slice(0, 300));
    const nDiff = await ev(() => document.querySelectorAll(".hy-d").length);
    await shot("before_after"); await noOvf("before/after"); await targets("before/after");
    await clickAct("hy-all"); await wait(300);
    ok("before/after: «Показать всё» adds the kept fields", (await ev(() => document.querySelectorAll(".hy-d").length)) >= nDiff);
    await clickAct("hy-share:0"); await wait(300);
    ok("before/after: «Поделиться чистой копией» uses the native share", /системный диалог/.test(await ev(() => (document.querySelector("#snack") || document.body).innerText)));
    // Partial clean (secret in the text): asks before sharing.
    await ev(() => { FOCA.state.v2.pf = { step: 1, files: [1], cleaned: [] }; FOCA.go("/p/preflight"); }); await wait(400);
    await clickAct("v2pf-clean:1"); await wait(600);
    t = await txt();
    ok("before/after: a copy with a secret in the text is not «чистая», sharing asks first", /Секрет в тексте/.test(t) && !/0 метаданных · файл валиден/.test(t), t.slice(0, 300));
    await clickAct("hy-share:0"); await wait(300);
    ok("before/after: confirmation sheet for a not fully clean copy", /Копия не полностью чистая/.test(await sheetTxt()));
    await closeSheet();

    // ---------- share target: shared file without a project ----------
    await ev(() => FOCA_DEMO_BACKEND.invokeSync("demo_share", {})); await ev(() => FOCA.emit("shared", {})); await wait(700);
    t = await txt();
    ok("share target: shared file opens the check screen (no project, no network) with a grade and steps", (await ev(() => FOCA.current())) === "/shared" && /Проект не создаётся/.test(t) && /Договір_оренди_2026\.pdf/.test(t) && (await ev(() => document.querySelectorAll(".hy-file .hy-g").length)) === 1 && /Документ подписан/.test(t), t.slice(0, 300));
    ok("share target: signed file → signature warning before cleaning", /Среди файлов есть подписанные/.test(t));
    await shot("shared"); await noOvf("shared file"); await targets("shared file");
    await clickAct("hy-sh-clean:0"); await wait(700);
    t = await txt();
    ok("share target: before/after with «Подпись снята», PDF revisions removed, pages kept, share button", (await ev(() => FOCA.current())) === "/clean/result" && /Подпись снята/.test(t) && /ревизии PDF/.test(t) && /страниц: 2 → 2/.test(t) && (await ev(() => !!document.querySelector('[data-act="hy-share:0"]'))), t.slice(0, 300));
    await shot("shared_result"); await noOvf("shared before/after");
    ok("share target: the shared list is handed out once", (await ev(() => FOCA_DEMO_BACKEND.invokeSync("platform_shared_files", {}).files.length)) === 0);

    // ---------- standards in the finding card ----------
    await ev(() => FOCA.api.project_open("contoso")); await wait(300);
    await go(`/p/finding/${await fid("doc.bad_redaction")}`); await wait(300);
    t = await txt();
    const stdc = await ev(() => [...document.querySelectorAll(".fd-stdc")].map(x => x.textContent));
    ok("finding card: standards chips ATT&CK / CWE / ISO 27001 / КСЗІ from finding.standards", stdc.includes("ATT&CK T1213") && stdc.includes("CWE-212") && stdc.includes("ISO 27001 A.8.12") && stdc.includes("КСЗІ 6.1.2.5") && /Стандарты/.test(t), stdc);
    ok("finding card: standards help link", await ev(() => !!document.querySelector('.fd-std [data-act="go:/help/standards"]')));
    await scrollTo(".fd-std"); await shot("finding_standards"); await noOvf("finding standards"); await targets("finding standards");
    const legacy = await ev(() => (FOCA.db.findings.find(f => !f.standards) || {}).id);
    await go(`/p/finding/${legacy}`); await wait(300);
    ok("finding card: no standards block for an unmapped rule", !(await ev(() => !!document.querySelector(".fd-std"))));

    // ---------- report builder: templates of the core ----------
    await go("/p/report-new"); await wait(400);
    const chips = await ev(() => [...document.querySelectorAll('.rp-tplc [role="radio"]')].map(x => x.textContent));
    ok("report builder: six template chips incl. Руководство / КСЗІ / Лабораторная", chips.join("|") === "Полный|Сводка|Данные|Руководство|КСЗІ|Лабораторная", chips);
    await clickAct("rp-d:tpl:compliance"); await wait(500);
    t = await txt();
    ok("report builder: КСЗІ template, core description in the report language, fixed structure, no section switches", /Находки × стандарты|Знахідки × стандарти/.test(t) && /Структура шаблона/.test(t) && /Оговорка аудитора/.test(t) && !(await ev(() => !!document.querySelector(".rp-secs"))), t.slice(0, 300));
    await shot("report_tpl_compliance"); await noOvf("report builder compliance"); await targets("report builder compliance");
    await clickAct("rp-d:lang:RU"); await wait(500);
    ok("report builder: description follows the report language (RU)", /КСЗИ \/ Соответствие/.test(await txt()));
    await clickAct("rp-preview"); await wait(500);
    t = await txt();
    ok("report preview: КСЗІ outline with the findings × standards table and the auditor caveat", /Стандарты/.test(t) && /CWE-212/.test(t) && /не заключение экспертизы КСЗІ/.test(t), t.slice(0, 300));
    await shot("report_preview_compliance"); await noOvf("report preview compliance");
    await go("/p/report-new"); await wait(300);
    await clickAct("rp-d:tpl:lab"); await wait(400);
    ok("report builder: laboratory work description", /Лабораторная работа/.test(await txt()) && /Выполнил \/ Проверил/.test(await txt()));
    const nRep = await ev(() => FOCA.db.reports.length);
    await clickAct("rp-build"); await wait(4200);
    const rep = await ev(() => FOCA.db.reports[0]);
    ok("report build: template passed to report_build (opts.tpl_id = lab, localized title)", (await ev(() => FOCA.db.reports.length)) === nRep + 1 && rep.opts.tpl_id === "lab" && rep.opts.template === "lab" && /Лаборатор/.test(rep.tpl), [rep.opts.tpl_id, rep.opts.template, rep.tpl]);
    await closeSheet();
    await go("/p/report-new"); await wait(300);
    await clickAct("rp-d:tpl:full"); await wait(400);
    ok("report builder: full template keeps the section switches", await ev(() => !!document.querySelector(".rp-secs")));
    await go("/p/reports"); await wait(300);
    ok("reports tab: cards of the new templates", await ev(() => ["executive", "compliance", "lab"].every(id => !!document.querySelector(`[data-act="rp-tpl:${id}"]`))));
    await noOvf("reports tab");

    // ---------- reference case ----------
    await go("/projects"); await wait(300);
    ok("projects: «Открыть эталонный кейс» entry", await ev(() => !!document.querySelector('.pj-offline [data-act="demo-case"]')));
    await shot("projects_democase"); await targets("projects demo case");
    const nProj = await ev(() => FOCA.projects.length);
    await clickAct("demo-case"); await wait(500);
    ok("reference case: import progress on the import screen", (await ev(() => FOCA.current())) === "/import" && /Импорт эталонного кейса/.test(await txt()));
    await shot("democase_progress");
    await wait(2500);
    ok("reference case: opens the new project «Эталонный кейс» with documents", (await ev(() => FOCA.current())) === "/p/overview" && (await ev(() => FOCA.db.project.name)) === "Эталонный кейс" && (await ev(() => FOCA.db.docs.length)) >= 10 && (await ev(() => FOCA.projects.length)) === nProj + 1, await ev(() => [FOCA.current(), FOCA.db.project && FOCA.db.project.name]));
    await go("/import"); await wait(300);
    ok("import screen: reference case entry", await ev(() => !!document.querySelector('.fx-democase [data-act="demo-case"]')));
    await clickAct("demo-case"); await wait(300);
    ok("reference case: second tap offers to open the existing project", /уже есть/.test(await sheetTxt()) && /Импортировать заново/.test(await sheetTxt()));
    await closeSheet();
    await go("/help/demo-case"); await wait(200);
    ok("help «Первые шаги»: button «Открыть эталонный кейс»", await ev(() => !!document.querySelector('.hl-go[data-act="demo-case"]')));
    await shot("help_democase"); await targets("help demo case");

    // ---------- help ----------
    for (const [id, re] of [["demo-case", /ТОВ «Приклад»/], ["report-templates", /Лабораторная/], ["standards", /не заключение государственной экспертизы КСЗІ/], ["graph-chain", /Цепочка связи/], ["netmap", /CDP\/AIA/], ["timeline-activity", /7 × 24/], ["anomalies", /сигнал для аналитика/], ["kev", /проверить версию/], ["org-chart", /обоснование/], ["webaudit", /Пассивный профиль/], ["hygiene", /Подпись снимается всегда/], ["share-target", /Проверить в FOCA-rs/]]) {
      await go(`/help/${id}`);
      ok(`help: ${id}`, re.test(await txt()));
      await noOvf(`help ${id}`);
    }
    await go("/help/kev"); await shot("help_kev");
    ok("no page errors", !errs.length, errs.slice(0, 3));
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/ins_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
