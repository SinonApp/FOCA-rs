// Demo: document forensics. Document card sections (signatures/КЕП, revisions with diff, bad redaction,
// hidden content, data connections, XMP history, PII, links, LNK/mail/calendar/contacts/media/ZIP), full-text
// search with safe snippets (also in the global search), offline import (folder → progress → cancel →
// result project), search rules (presets, own regex, "test", errors), forensic finding codes with a link to
// the document, document types of the wizard, help articles; no horizontal overflow at every step.
// qa/shoot.sh --routes /p/overview --out $PWD/qa/out/fx --w 393 --steps $PWD/qa/scenarios/forensics-1-3/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(250); await page.screenshot({ path: `${out}/fx_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const noOvf = async n => { const v = await overflow(); console.log(`STEP ${n.replace(/\s+/g, "_")} overflow [${v > 1 ? v : 0}]`); ok(`${n}: no horizontal overflow`, v <= 1, v); };
  const scrollTo = sel => ev(s => { const el = document.querySelector(s); if (el) el.scrollIntoView({ block: "start" }); return !!el; }, sel);
  const clickAct = act => ev(a => { const b = document.querySelector(`[data-act="${a}"]`); if (b) b.click(); return !!b; }, act);
  const openAll = () => ev(() => document.querySelectorAll(".fx-sec").forEach(d => { d.open = true; }));
  // Tap targets of the visible interactive elements inside the page (≥ 44 × 44 px; inline text links excluded).
  // Same rules as regression-round2/a11y: pseudo-elements and wrapping rows extend the hit area.
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
  const docId = name => ev(n => (FOCA.db.docs.find(d => d.name === n) || {}).id, name);
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);

    // ---------- document card: signed PDF ----------
    const tu = await docId("Технічні_умови_підключення.pdf");
    ok("demo: signed PDF is in the project with the forensic flag", !!tu && (await ev(id => FOCA.db.docs.find(d => d.id === id).flags.includes("forensic"), tu)));
    await go(`/p/doc/${tu}`); await wait(200);
    let t = await txt();
    ok("doc card: \"Форензика\" with collapsed sections", /Форензика/.test(t) && (await ev(() => document.querySelectorAll(".fx-sec").length)) >= 6 && (await ev(() => [...document.querySelectorAll(".fx-sec")].every(d => !d.open))), t.slice(0, 200));
    ok("doc card: section titles (signatures, redaction, revisions, PII, links, XMP)", ["Подписи и КЕП", "Плохое замазывание", "Ревизии PDF", "Персональные данные", "Облачные ссылки и токены", "История правок (XMP)"].every(s => t.includes(s)));
    await scrollTo(".fx-secs"); await shot("doc_pdf_closed"); await noOvf("doc card sections closed");
    await openAll(); await wait(200);
    t = await txt();
    ok("signature: signer, organization, ЄДРПОУ, РНОКПП mask only, АЦСК, TSA, edits after signing", /Приклад Петро Тестович/.test(t) && /ТОВ «Контосо Енерджі»/.test(t) && /12345678/.test(t) && /\*{8}57/.test(t) && !/TINUA-\d{10}/.test(t) && /КНЕДП - ІДД ДПС/.test(t) && /Метка TSA/.test(t) && /Правки после подписания/.test(t) && /расходится с временем подписи на 3 дня/.test(t), t.slice(0, 400));
    ok("revisions: timeline with removed (−) and added (+) lines", (await ev(() => document.querySelectorAll(".fx-diff.del").length)) === 2 && (await ev(() => document.querySelectorAll(".fx-diff.ins").length)) === 1 && /Ревизия 3/.test(t));
    ok("bad redaction: page, fill and short fragment", /Стр\. 3/.test(t) && /Чёрная заливка/.test(t) && /Резервна лінія: ПС-35/.test(t));
    ok("PII: types, counts, masked samples", /Телефон · 3 значения/.test(t) && /РНОКПП \(ІПН\) · 1 значение/.test(t) && /••• •• 14/.test(t));
    ok("links: service, masked token, SAS pill", /Azure Storage/.test(t) && /SAS-подпись Azure: sig/.test(t) && /sig=••••••••/.test(t));
    ok("XMP: history events and document id", /Конвертирован/.test(t) && /Acrobat PDFMaker 11/.test(t) && /DocumentID/.test(t));
    await scrollTo('[data-fx="sig"]'); await shot("doc_pdf_sig"); await noOvf("signature section");
    await scrollTo('[data-fx="rev"]'); await shot("doc_pdf_rev");
    await scrollTo('[data-fx="red"]'); await shot("doc_pdf_red"); await noOvf("doc card sections open");
    const small = await smallTargets();
    ok("doc card: tap targets ≥ 44 px", !small.length, small.slice(0, 6));
    // Open state survives a re-render (navigation between documents keeps the chosen sections).
    await ev(() => FOCA.render(true)); await wait(150);
    ok("doc card: open sections survive a re-render", await ev(() => document.querySelector('[data-fx="sig"]').open));
    await ev(() => document.querySelectorAll(".fx-sec").forEach(d => { d.open = false; d.dispatchEvent(new Event("toggle")); })); await wait(100);

    // ---------- hidden content, data connections ----------
    await go(`/p/doc/${await docId("Перелік_обладнання_ТЕС-2.xlsx")}`); await openAll(); await wait(150);
    t = await txt();
    ok("xlsx: hidden rows, columns and sheet; data connection and pivot cache", /Скрытые строки/.test(t) && /Обладнання!12:14/.test(t) && /Скрытые столбцы/.test(t) && /Скрытый лист/.test(t) && /Подключение «ERP_Billing»/.test(t) && /svc_report/.test(t) && /Сводная таблица \(pivotCache1\)/.test(t) && /SRV-SQL02/.test(t), t.slice(0, 300));
    await scrollTo(".fx-secs"); await shot("doc_xlsx"); await noOvf("xlsx hidden content");
    await go("/p/doc/1"); await openAll(); await wait(150);
    t = await txt();
    ok("docx: w:vanish hidden text, IBAN masked, SharePoint link", /Скрытый текст \(w:vanish\)/.test(t) && /Знижка 8%/.test(t) && /••••4417/.test(t) && /SharePoint/.test(t));
    await noOvf("docx hidden text");
    ok("docx: every font name is listed in the open fonts section", await ev(() => { const d = document.querySelector('[data-fx="fonts"]'); return !!d && d.open && ["Calibri", "Times New Roman", "Segoe UI Symbol"].every(f => d.textContent.includes(f)); }));
    await scrollTo('[data-fx="fonts"]'); await shot("doc_docx_fonts");

    // ---------- format details ----------
    await go(`/p/doc/${await docId("Звіти.lnk")}`); await openAll(); await wait(150);
    t = await txt();
    ok("LNK: computer, MAC, volume, UNC path", /Ярлык Windows/.test(t) && /buh-pc07/.test(t) && /3c:52:82:4a:1f:0b/.test(t) && /6A2F-91C4/.test(t) && /Сетевой путь \(UNC\)/.test(t) && /SRV-FILE01/.test(t));
    await scrollTo(".fx-secs"); await shot("doc_lnk"); await noOvf("lnk details");
    await go(`/p/doc/${await docId("Re_Тендер_ТЕС-2_уточнення.eml")}`); await openAll(); await wait(150);
    t = await txt();
    ok("EML: sender, Reply-To differs, Received chain with internal IPs marked", /Заголовки письма/.test(t) && /Сергій Лисенко/.test(t) && /lysenko\.serhii@example\.net/.test(t) && /отличается от отправителя/.test(t) && /Цепочка Received \(3\)/.test(t) && (await ev(() => document.querySelectorAll(".fx-rcv mark").length)) >= 3 && /Кошторис_ТЕС-2_v2\.xlsx/.test(t), t.slice(0, 300));
    await scrollTo('[data-fx="fmt"]'); await shot("doc_eml"); await noOvf("eml headers");
    await go(`/p/doc/${await docId("Нарада_ТЕС-2_графік.ics")}`); await openAll(); await wait(150);
    t = await txt();
    ok("ICS: event, organizer, meeting link", /Календарь/.test(t) && /Нарада: графік робіт ТЕС-2/.test(t) && /i\.petrenko@contoso\.example/.test(t) && /teams\.microsoft\.com/.test(t));
    await noOvf("ics details");
    await go(`/p/doc/${await docId("Контакти_відділу_продажів.vcf")}`); await openAll(); await wait(150);
    t = await txt();
    ok("VCF: contacts with masked phones and birthday", /Контакты/.test(t) && /Сергій Лисенко/.test(t) && /\+380 50 ••• •• 08/.test(t) && /Дата рождения/.test(t));
    await noOvf("vcf details");
    await go(`/p/doc/${await docId("IMG_4131.mp4")}`); await openAll(); await wait(150);
    t = await txt();
    ok("MP4: device, serial, GPS", /Медиафайл/.test(t) && /iPhone 13 Pro/.test(t) && /F2LX••••Q1PK/.test(t) && /Кривий Ріг/.test(t));
    await noOvf("media details");
    await go(`/p/doc/${await docId("Тендер_ТЕС-2_додатки.zip")}`); await openAll(); await wait(150);
    t = await txt();
    ok("ZIP: files in the archive, Zip-Slip path marked", /Файлы в архиве/.test(t) && /Опасный путь \(Zip-Slip\)/.test(t) && /update\.lnk/.test(t));
    await scrollTo(".fx-secs"); await shot("doc_zip"); await noOvf("zip details");

    // ---------- findings: codes, notes, link to the document ----------
    const f = await ev(() => FOCA.db.findings.find(x => x.provenance.rule === "doc.bad_redaction"));
    ok("finding doc.bad_redaction exists (critical)", f && f.sev === "crit");
    if (f) {
      await go(`/p/finding/${f.id}`);
      t = await txt();
      ok("finding card: code note and \"К документу\"", /остался в PDF/.test(t) && (await ev(id => !!document.querySelector(`[data-act="go:/p/doc/${id}"]`), f.provenance.doc)), t.slice(0, 300));
      await clickAct(`go:/p/doc/${f.provenance.doc}`); await wait(450);
      ok("\"К документу\" opens the document card", (await ev(() => FOCA.current())) === `/p/doc/${f.provenance.doc}`);
    }
    const codes = await ev(() => [...new Set(FOCA.db.findings.map(x => x.provenance.rule).filter(r => r && !/^infra\./.test(r)))]);
    ok("findings: every forensic code has a note", await ev(cs => cs.every(c => !!FOCA.fx.CODE[c]), codes), codes);
    const pf = await ev(() => FOCA.db.findings.find(x => x.provenance.rule === "pii" && /карты/.test(x.title)));
    if (pf) { await go(`/p/finding/${pf.id}`); t = await txt(); ok("PII finding: category \"Люди и e-mail\", masked evidence", /Люди и e-mail/.test(t) && /•••• •••• •••• 4471/.test(t) && !/\b\d{16}\b/.test(t)); await noOvf("pii finding"); }

    // ---------- documents list: flags and full-text search ----------
    await go("/p/data/docs");
    ok("docs: \"Поиск по тексту документов\" entry", await ev(() => !!document.querySelector('.fx-ftsb[data-act="go:/p/docs-search"]')));
    await clickAct("go:/p/docs-search"); await wait(400);
    t = await txt();
    ok("docs search: hints before typing", /Точная фраза/.test(t) && /64 КБ/.test(t));
    await page.fill("#fts-q", "ТЕС-2"); await wait(500);
    t = await txt();
    ok("docs search: results with highlighted snippets", /Найдено: \d+ документ/.test(t) && (await ev(() => document.querySelectorAll(".fx-hit mark.fx-hl").length)) >= 3, t.slice(0, 200));
    await shot("fts"); await noOvf("docs search");
    await page.fill("#fts-q", "IBAN"); await wait(500);
    t = await txt();
    ok("docs search: masked values shown masked with \"В фрагменте скрыто\"", /В фрагменте скрыто: IBAN/.test(t) && (await ev(() => document.querySelectorAll(".fx-hit .fx-mask").length)) > 0 && !/UA\d{6,}/.test(t));
    // Safe rendering: markup in the document text is shown as text, never executed.
    const xss = await ev(() => { const h = FOCA.fx.snippet('<img src=x onerror="window.__x=1">{{h:<b>x</b>}}{{s:<i>••</i>}}'); const d = document.createElement("div"); d.innerHTML = h; return { img: !!d.querySelector("img"), b: !!d.querySelector("b"), i: !!d.querySelector("i"), mark: d.querySelectorAll("mark").length, mask: d.querySelectorAll(".fx-mask").length }; });
    ok("snippet: only highlight/mask markup, document text escaped", !xss.img && !xss.b && !xss.i && xss.mark === 1 && xss.mask === 1, xss);
    await page.fill("#fts-q", "диспетчера"); await wait(500);
    await ev(() => document.querySelector(".fx-hit").click()); await wait(450);
    ok("docs search: a result opens the document card", (await ev(() => FOCA.current())) === `/p/doc/${tu}`);
    // Global search shows text matches too.
    await go("/p/search");
    await page.fill("#gq", "знижка"); await wait(500);
    t = await txt();
    ok("global search: \"В тексте документов\" section", /В тексте документов/.test(t) && /Перелік_обладнання_ТЕС-2\.xlsx/.test(t), t.slice(0, 300));
    await noOvf("global search");

    // ---------- wizard: document types ----------
    await go("/new");
    await ev(() => { const b = [...document.querySelectorAll("summary, button")].find(x => /Дополнительно/.test(x.textContent)); if (b) b.click(); }); await wait(300);
    const types = await ev(() => [...document.querySelectorAll(".la-docs .chip")].map(c => c.textContent.slice(1)));
    ok("wizard: 1.3 and beta.4 formats in the document types (grouped)", ["eml", "msg", "ics", "vcf", "vsdx", "vsd", "pub", "mp4", "mov", "zip", "heic", "rtf", "exe", "msi", "jar", "apk", "dwg", "dxf", "eps", "tar", "wav", "mkv", "kml", "gpx", "map", "ipynb"].every(x => types.includes(x)) && (await ev(() => document.querySelectorAll(".la-dg").length)) === 9, types.join(" "));
    if (await scrollTo(".la-dg")) { await shot("wizard_types"); }
    await noOvf("wizard document types");

    // ---------- search rules ----------
    await go("/p/scope");
    ok("scope: \"Правила поиска\" row", await ev(() => !!document.querySelector('.la-rules [data-act="go:/p/rules"]')));
    await go("/p/rules"); await wait(300);
    t = await txt();
    ok("rules: five presets of the core with toggles", ["Документы госорганов Украины", "Учётные данные в тексте", "Внутренняя инфраструктура", "Криптовалютные кошельки", "Персональные данные (свободная форма)"].every(s => t.includes(s)) && (await ev(() => document.querySelectorAll(".fx-preset .toggle").length)) === 5, t.slice(0, 300));
    await clickAct("rule-preset:credentials"); await clickAct("rule-add"); await wait(300);
    await page.fill(".fx-rule [data-rf=title]", "Номер договору");
    await page.fill(".fx-rule [data-rf=pattern]", "договір\\s*№\\s*(?P<v>[\\d/-]+)");
    await ev(() => { document.querySelector(".fx-rtest").open = true; });
    await page.fill(".fx-rule [data-rf=sample]", "Згідно з договір № 14/03-24 від 11.03.2024");
    const rid = await ev(() => document.querySelector(".fx-rule").dataset.rule);
    await clickAct(`rule-test:${rid}`); await wait(300);
    t = await txt();
    ok("rules: \"Проверить\" shows matches highlighted and masked values", /Совпадений: 1/.test(t) && (await ev(() => document.querySelector(".fx-tres mark").textContent)) === "договір № 14/03-24" && /••••24/.test(t), t.slice(-400));
    await scrollTo(".fx-rule"); await shot("rules_test"); await noOvf("rules test");
    await page.fill(".fx-rule [data-rf=pattern]", "(договір");
    await clickAct(`rule-test:${rid}`); await wait(300);
    ok("rules: broken pattern → readable error under the test", /ошибка в шаблоне/.test(await txt()));
    await clickAct("rules-save"); await wait(300);
    ok("rules: saving a broken pattern shows the error on the rule card", await ev(() => document.querySelector(".fx-rule").classList.contains("bad") && /ошибка в шаблоне/.test(document.querySelector(".fx-rule .fx-err").textContent)));
    await page.fill(".fx-rule [data-rf=pattern]", "договір\\s*№\\s*(?P<v>[\\d/-]+)");
    await clickAct("rules-save"); await wait(300);
    const cfg = await ev(() => FOCA.api.rules_get().then(r => r.config));
    ok("rules: saved config (preset + own rule)", cfg.presets.includes("credentials") && cfg.rules.some(r => r.title === "Номер договору" && r.sev === "warn"), cfg);
    await noOvf("rules screen");
    const smallR = await smallTargets();
    ok("rules: tap targets ≥ 44 px", !smallR.length, smallR.slice(0, 6));

    // ---------- offline import ----------
    await go("/projects");
    ok("projects: \"Разобрать файлы без сети\" entry", await ev(() => !!document.querySelector('.pj-offline [data-act="go:/import"]')));
    await clickAct("go:/import"); await wait(400);
    t = await txt();
    ok("import: offline banner, folder / files buttons, start disabled", /Без сети/.test(t) && /не покидают устройство/.test(t) && (await ev(() => document.querySelector('[data-act="imp-start"]').disabled)));
    await shot("import_idle"); await noOvf("import idle");
    await clickAct("imp-pick:folder"); await wait(300);
    t = await txt();
    ok("import: picked folder summary", /8 файлов/.test(t) && /Технічні_умови_підключення\.pdf/.test(t) && /и ещё 3/.test(t));
    await page.fill("#imp-name", "Флешка заказчика");
    // Cancel during the progress.
    await clickAct("imp-start"); await wait(500);
    ok("import: progress with file name and cancel", await ev(() => !!document.querySelector(".fx-prog .pbar") && !!document.querySelector('[data-act="imp-cancel"]')));
    await shot("import_progress");
    await clickAct("imp-cancel"); await wait(600);
    t = await txt();
    ok("import: cancelled → result says so", /Разбор отменён/.test(t), t.slice(0, 200));
    await clickAct("imp-again"); await wait(300);
    await clickAct("imp-pick:folder"); await wait(300);
    const before = await ev(() => FOCA.projects.length);
    await clickAct("imp-start"); await wait(2600);
    t = await txt();
    ok("import: result, documents added, open project", /Разбор завершён/.test(t) && /Добавлено документов\s*8/.test(t) && (await ev(() => FOCA.projects.length)) === before + 1, t.slice(0, 300));
    await shot("import_done"); await noOvf("import result");
    await ev(() => document.querySelector('[data-act^="imp-open:"]').click()); await wait(700);
    const pj = await ev(() => ({ cur: FOCA.current(), name: FOCA.db.project.name, docs: FOCA.db.docs.length, f: FOCA.db.findings.length, scans: FOCA.db.scans.length }));
    ok("import: project with documents and findings, no scans", pj.cur === "/p/overview" && pj.name === "Флешка заказчика" && pj.docs === 8 && pj.f > 10 && pj.scans === 0, pj);
    await noOvf("imported project overview");

    // ---------- help ----------
    for (const [id, re] of [["forensics-help", /Плохое замазывание/], ["formats-help", /\.eml/], ["kep-help", /РНОКПП показывается только маской/], ["redaction-help", /Redact → Apply/], ["pii-help", /контрольным суммам/], ["fts-help", /64 КБ/], ["rules-help", /\(\?P&lt;v&gt;|\(\?P<v>/], ["offline-help", /не покидают устройство/]]) {
      await go(`/help/${id}`);
      ok(`help: ${id}`, re.test(await txt()));
      await noOvf(`help ${id}`);
    }
    await go("/help/kep-help"); await shot("help_kep");
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/fx_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
