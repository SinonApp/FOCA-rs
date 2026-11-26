// Demo: infrastructure data (infra_get). Host roles/priority/source/CDN in the hosts list and the host card
// with its certificate block; data segments "Сертификаты", "Почтовые политики", "SaaS и CDN"; out-of-scope
// candidates marked "not checked"; the wizard (profiles = core default_modules, module kinds, brute force
// wordlist sent in scan_start); subdomains/tls scan sources; infra finding categories and code notes; help.
// qa/shoot.sh --routes /p/overview --out $PWD/qa/out/infra --w 393 --steps $PWD/qa/scenarios/infra-1-2/steps.mjs
import fs from "fs";
export default async (page, { out, W, fsc, theme }) => {
  const log = []; let fails = 0;
  const ok = (name, cond, data) => { if (!cond) fails++; log.push([cond ? "OK" : "FAIL", name, data]); };
  const ev = (f, a) => page.evaluate(f, a);
  const wait = ms => page.waitForTimeout(ms);
  const go = async r => { await ev(r => FOCA.go(r), r); await wait(450); };
  const txt = () => ev(() => (FOCA.page() || document.querySelector(".page")).textContent);
  const tag = `${W}_fs${fsc || 1}_${theme}`;
  const shot = async n => { await wait(300); await page.screenshot({ path: `${out}/infra_${n}_${tag}.png` }); };
  const overflow = () => ev(() => Math.max(document.documentElement.scrollWidth - innerWidth, (FOCA.page() || document.body).scrollWidth - (FOCA.page() || document.body).clientWidth));
  const noOvf = async n => { const v = await overflow(); console.log(`STEP ${n.replace(/\s+/g, "_")} overflow [${v > 1 ? v : 0}]`); ok(`${n}: no horizontal overflow`, v <= 1, v); };
  const scrollTo = sel => ev(s => { const el = document.querySelector(s); if (el) el.scrollIntoView({ block: "center" }); return !!el; }, sel);
  const clickAct = act => ev(a => { const b = document.querySelector(`[data-act="${a}"]`); if (b) b.click(); return !!b; }, act);
  try {
    await page.goto(new URL("../../../ui/index.html#/projects", import.meta.url).href); await wait(400);
    await ev(() => FOCA.api.demo_reset()); await wait(150);
    await ev(() => FOCA.api.terms_accept("1")); await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    const inf = await ev(() => FOCA.db.infra);
    ok("F.db.infra loaded from infra_get", inf && inf.cert.length > 0 && inf.saas.length === 1 && inf.tenant.length === 1, inf && Object.fromEntries(Object.entries(inf).map(([k, v]) => [k, v.length])));

    // Hosts: role chips, check priority, discovery source, CDN label; enumeration summary; priority sort.
    await go("/p/data/hosts");
    let t = await txt();
    ok("hosts: role chips (Тест / стейдж, Удалённый доступ)", /Тест \/ стейдж/.test(t) && /Удалённый доступ/.test(t), t.slice(0, 300));
    ok("hosts: discovery source (Перебор поддоменов, Арендатор Microsoft 365)", /Перебор поддоменов/.test(t) && /Арендатор Microsoft 365/.test(t));
    ok("hosts: CDN label (CDN · Cloudflare, Облако · Amazon)", /CDN · Cloudflare/.test(t) && /Облако · Amazon Web Services/.test(t));
    ok("hosts: brute force summary (wordlist, tried, found)", /перебор top-5000: проверено 5000, найдено/.test(t), (t.match(/перебор[^\n]{0,120}/) || [""])[0]);
    await ev(() => FOCA.actions["dt-sort-set"]("hosts:prio")); await wait(300);
    const first = await ev(() => (document.querySelector(".dt-segbody .list .row .t") || {}).textContent);
    ok("hosts: \"Приоритет проверки\" sort puts the remote access host first", /vpn\.contoso\.example/.test(first || ""), first);
    await shot("hosts"); await noOvf("hosts list");
    await ev(() => FOCA.actions["dt-sort-set"]("hosts:sev")); await wait(200);

    // Host card: source label, CDN, priority, certificate block from infra_get.cert.
    await go("/p/entity/host/staging.contoso.example");
    t = await txt();
    ok("host card: source \"Перебор поддоменов\", priority, role", /Источник\s*Перебор поддоменов/.test(t) && /Приоритет проверки\s*30 из 100/.test(t) && /Тест \/ стейдж/.test(t), t.slice(0, 500));
    ok("host card: certificate block (subject, issuer, trust, SHA-256, SPKI)", /Сертификат TLS/.test(t) && /Доверенный/.test(t) && /SHA-256/.test(t) && /SPKI/.test(t));
    await go("/p/entity/host/cdn.contoso.example");
    t = await txt();
    ok("cdn host card: CDN row and \"Скоро истекает\" issue, expiry warning", /CDN \/ облако\s*Cloudflare/.test(t) && /Скоро истекает/.test(t) && /через 9 дней/.test(t), t.slice(0, 600));
    await scrollTo(".if-cert"); await shot("host_cert"); await noOvf("host card certificate");

    // Data segments.
    await go("/p/data/certs");
    t = await txt();
    ok("certs: list with count and issues, CT history, abandoned name", /7 сертификатов · с замечаниями 1/.test(t) && /История сертификатов \(CT\)/.test(t) && /Заброшенные имена \(CT\)/.test(t) && /old\.contoso\.example/.test(t), t.slice(0, 300));
    ok("certs: help link to the TLS article", await ev(() => !!document.querySelector('[data-act="go:/help/tls-help"]')));
    await shot("certs"); await noOvf("certs segment");
    await go("/p/data/mailpol");
    t = await txt();
    ok("mail policies: MTA-STS / TLS-RPT / BIMI / CAA / DNSSEC and issues", /MTA-STS/.test(t) && /TLS-RPT/.test(t) && /BIMI/.test(t) && /letsencrypt\.org/.test(t) && /Не подписана/.test(t) && /Нет MTA-STS/.test(t), t.slice(0, 400));
    await shot("mailpol"); await noOvf("mail policies segment");
    await go("/p/data/saas");
    t = await txt();
    ok("saas: services by category (Microsoft 365, Google)", /Microsoft 365/.test(t) && /Google/.test(t) && /Офис и почта/.test(t));
    const tid = inf && inf.tenant[0] && inf.tenant[0].openid.tenant_id;
    ok("saas: M365 tenant id, federation via AD FS (sts)", tid && t.includes(tid) && /Федерация/.test(t) && /sts\.contoso\.example/.test(t));
    ok("saas: CDN/clouds and origin candidates \"для проверки\"", /CDN и облака/.test(t) && /Кандидаты origin за CDN/.test(t) && /для проверки/.test(t) && /203\.0\.113\.10/.test(t));
    ok("saas: out-of-scope candidates with an explicit \"not checked, out of scope\" mark", /Кандидаты вне скоупа/.test(t) && /Не проверялись, вне скоупа/.test(t) && /contoso\.example\.net/.test(t) && /Домен арендатора M365/.test(t) && /не проверялся/.test(t));
    await scrollTo(".if-tenant"); await shot("saas_tenant");
    await scrollTo(".if-oos-b"); await shot("saas_oos"); await noOvf("saas segment");

    // Out-of-scope screen: the infra candidates carry their source and the "not checked" mark.
    await go("/p/out-of-scope");
    t = await txt();
    ok("out of scope: tenant domain and O= pivot candidates, \"Не проверялся, вне скоупа\"", /contoso\.example\.net/.test(t) && /contoso-trade\.example/.test(t) && /Не проверялся, вне скоупа/.test(t) && /Та же организация \(O=\)/.test(t), t.slice(0, 300));
    await scrollTo(".scn-ounchk"); await shot("oos"); await noOvf("out-of-scope screen");

    // Findings: infra categories and the code note.
    const f = await ev(() => FOCA.db.findings.find(x => x.provenance.rule === "infra.host_role_exposed"));
    ok("finding: provenance.rule kept for infra findings", !!f, null);
    if (f) {
      await go(`/p/finding/${f.id}`);
      t = await txt();
      ok("finding card: category \"Хосты и роли\" and the code note", /Хосты и роли/.test(t) && /Служебный хост \(тест, админка, CI, база\) доступен из интернета/.test(t), t.slice(0, 500));
      await noOvf("infra finding card");
    }
    const f2 = await ev(() => FOCA.db.findings.find(x => x.provenance.rule === "infra.cert_expires_soon"));
    if (f2) {
      await go(`/p/finding/${f2.id}`);
      ok("finding card: category \"TLS и сертификаты\"", /TLS и сертификаты/.test(await txt()));
    }

    // Wizard: profile modules = core default_modules; module kinds; wordlist block and scan_start.subdomains.
    await go("/new");
    await clickAct("la-prof:std"); await wait(300);
    t = await txt();
    ok("wizard std: \"Перебор поддоменов\" block with Выкл / Топ-1500 / Топ-5000 / Свой, Топ-1500 by default", /Перебор поддоменов/.test(t) && /Выкл/.test(t) && /Топ-5000/.test(t) && await ev(() => document.querySelector('[data-act="la-sub-wl:top-1500"]').classList.contains("on")), t.slice(0, 200));
    await scrollTo(".la-sub-seg"); await shot("wizard_std"); await noOvf("wizard std");
    await clickAct("la-prof:full"); await wait(300);
    ok("wizard full: Топ-5000 by default", await ev(() => document.querySelector('[data-act="la-sub-wl:top-5000"]').classList.contains("on")));
    await clickAct("la-prof:passive"); await wait(300);
    ok("wizard passive: no brute force block", !(await ev(() => !!document.getElementById("la-sub"))));
    await clickAct("la-prof:custom"); await wait(300);
    t = await txt();
    ok("wizard custom: modules infra / subdomains / tls / nsec listed", /Инфраструктура по DNS/.test(t) && /Перебор поддоменов/.test(t) && /Проверка TLS-сертификатов/.test(t) && /Обход зоны \(NSEC\)/.test(t));
    const kinds = await ev(() => Object.fromEntries([...document.querySelectorAll(".la-mod")].map(r => [r.querySelector(".t").textContent, r.querySelector(".la-src-p").textContent])));
    ok("wizard custom: module kinds (infra passive, subdomains/tls target, nsec active)", /Пассив|внешн/i.test(kinds["Инфраструктура по DNS"] || "") && !/Пассив|внешн/i.test(kinds["Перебор поддоменов"] || "x") && kinds["Обход зоны (NSEC)"] !== kinds["Перебор поддоменов"], kinds);
    await scrollTo(".la-mods"); await shot("wizard_custom"); await noOvf("wizard custom");
    // Start a standard scan with a custom wordlist and check what reaches the backend.
    await ev(() => {
      window.__args = [];
      const B = window.FOCA_DEMO_BACKEND, orig = B.invokeSync;
      B.invokeSync = (cmd, a) => { if (cmd === "scan_start") window.__args.push(JSON.parse(JSON.stringify(a))); return orig.call(B, cmd, a); };
    });
    await clickAct("la-prof:std"); await wait(250);
    await clickAct("la-sub-wl:custom"); await wait(250);
    await ev(() => { const ta = document.getElementById("la-sub-words"); ta.value = "vpn\nportal, crm"; ta.dispatchEvent(new Event("input", { bubbles: true })); });
    ok("wizard: custom words counted", /Слов: 3/.test(await txt()));
    await clickAct("la-start"); await wait(500);
    const a = await ev(() => window.__args.slice(-1)[0]);
    ok("scan_start: subdomains { wordlist: custom, custom: [vpn, portal, crm] } and std modules", a && a.subdomains && a.subdomains.wordlist === "custom" && JSON.stringify(a.subdomains.custom) === '["vpn","portal","crm"]' && ["infra", "subdomains", "tls"].every(m => a.modules.includes(m)) && !a.modules.includes("nsec"), a);
    // Scan sources: subdomains / tls are listed with statuses; skip is offered during the network stage.
    await ev(() => FOCA.api.scan_pause()); await wait(150);
    let src = await ev(() => (FOCA.scan.sources || []).filter(s => s.id === "subdomains" || s.id === "tls").map(s => [s.id, s.status]));
    ok("scan: subdomains and tls sources waiting", JSON.stringify(src) === '[["subdomains","wait"],["tls","wait"]]', src);
    await go("/p/scan");
    t = await txt();
    ok("scan screen: \"Перебор и перестановки поддоменов\" and \"TLS/X.509-инспектор\" rows", /Перебор и перестановки поддоменов/.test(t) && /TLS\/X\.509-инспектор/.test(t));
    await ev(() => FOCA.api.scan_stop()); await wait(300);
    await ev(() => FOCA.api.project_open("contoso")); await wait(250);
    // Passive scan: the sources are not shown at all (active-only sources).
    await ev(() => FOCA.actions["scan-start"]({ profile: "passive" })); await wait(300);
    await ev(() => FOCA.api.scan_pause()); await wait(150);
    src = await ev(() => (FOCA.scan.sources || []).filter(s => s.id === "subdomains" || s.id === "tls").length);
    ok("passive scan: no subdomains/tls sources", src === 0, src);
    await ev(() => FOCA.api.scan_stop()); await wait(300);

    // Settings → Sources and help.
    await go("/settings/sources");
    await ev(() => { ["sub", "intel"].forEach(g => { const b = document.querySelector(`[data-act="src-open:${g}"]`); if (b && b.getAttribute("aria-expanded") !== "true") b.click(); }); }); await wait(300);
    t = await txt();
    ok("sources: brute force (\"Запросы к DNS цели\") and TLS inspector listed", /Перебор и перестановки поддоменов/.test(t) && /Запросы к DNS цели/.test(t) && /TLS\/X\.509-инспектор/.test(t));
    await noOvf("sources");
    for (const [id, re] of [["subdomains-help", /DNS-запрос/], ["tls-help", /CAA/], ["m365-help", /AD FS/], ["oos-help", /ни одного запроса/]]) {
      await go(`/help/${id}`);
      ok(`help: ${id}`, re.test(await txt()));
      await noOvf(`help ${id}`);
    }
    await go("/help/subdomains-help"); await shot("help_subdomains");
  } catch (e) { fails++; log.push(["FAIL", "exception", String(e && e.stack || e)]); }
  fs.writeFileSync(`${out}/infra_steps_${tag}.json`, JSON.stringify({ fails, log }, null, 1));
  console.log(log.map(x => `  ${x[0]} ${x[1]}${x[0] === "FAIL" ? " " + JSON.stringify(x[2] || "").slice(0, 300) : ""}`).join("\n"));
  console.log(`${log.length - fails} OK, ${fails} FAIL`);
};
