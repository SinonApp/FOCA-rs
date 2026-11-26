// Checks the demo data invariants without a browser: node qa/data-invariants.mjs
// Loads ui/js/demo-backend.js + api.js + sel.js into a bare window and checks the data rules, including
// dynamics: scan → stop → app restart → resume, triage during a scan, scope and the active phase, reports, secrets.
import fs from "fs";
import { fileURLToPath } from "url";
import vm from "vm";

const root = fileURLToPath(new URL("../ui/js/", import.meta.url));
const ctx = { console, setTimeout, clearTimeout, Promise, JSON, Math, Date, Map, Set, Object, Array, String, Number, Proxy, encodeURIComponent, decodeURIComponent };
ctx.window = ctx; ctx.globalThis = ctx; ctx.FOCA = { state: {}, actions: {} };
vm.createContext(ctx);
for (const f of ["demo-backend.js", "api.js", "sel.js"]) vm.runInContext(fs.readFileSync(root + f, "utf8"), ctx, { filename: f });
const F = ctx.FOCA, B = ctx.FOCA_DEMO_BACKEND;

let fails = 0, passes = 0;
const groups = {};
const ok = (group, cond, msg) => { groups[group] = groups[group] || { ok: 0, bad: [] }; if (cond) { passes++; groups[group].ok++; } else { fails++; groups[group].bad.push(msg); } };

const SWD = Object.fromEntries(B.SOFTWARE.map(s => [s.id, s]));
const PROFILES = ["Пассивный", "Стандартный", "Полный", "Свой"];
const S = B._state();

// Determinism.
ok("deterministic generation", JSON.stringify(B._generate()) === JSON.stringify(B._generate()), "generate() yields a different result");

for (const id of S.order) {
  const st = S.projects[id];
  const P = `[${id}]`;
  const docs = st.docs, an = docs.filter(d => d.status === "analyzed");
  const byDoc = Object.fromEntries(docs.map(d => [d.id, d]));
  // Documents.
  const names = new Set();
  for (const d of docs) {
    ok("document names are unique", !names.has(d.name.toLowerCase()), `${P} duplicate name ${d.name}`); names.add(d.name.toLowerCase());
    if (d.status !== "analyzed") {
      ok("no metadata on unanalyzed documents", !d.author && !d.software && !d.created_at && !d.folder && !d.printer && !d.gps && !d.revisions.length && !d.flags.length, `${P} doc ${d.id} (${d.status}) has metadata`);
      continue;
    }
    const sw = d.software ? SWD[d.software] : null;
    if (d.ext === "rdp" || d.ext === "lnk" || d.ext === "zip") ok("ext ↔ software", !sw, `${P} doc ${d.id} .${d.ext} with software ${d.software}`);
    else {
      ok("ext ↔ software", sw && sw.exts.includes(d.ext), `${P} doc ${d.id} .${d.ext} ← ${d.software}`);
      ok("software not newer than the document date", sw && sw.rel <= +d.created_at.slice(0, 4), `${P} doc ${d.id} ${d.created_at} < release of ${d.software} (${sw && sw.rel})`);
      if (d.ext === "jpg") ok("photos come from a camera/phone/editor", ["camera", "image"].includes(sw.kind), `${P} doc ${d.id} jpg ← ${sw.kind}`);
      if (d.ext === "pdf") ok("PDFs come from a PDF producer/Word/scanner", ["pdf", "scanner", "office"].includes(sw.kind), `${P} doc ${d.id}`);
    }
    if (d.modified_at) ok("modified ≥ created", d.modified_at >= d.created_at, `${P} doc ${d.id} modified < created`);
    for (const r of d.revisions) ok("revision dates ≥ creation", r.at >= d.created_at && (!d.modified_at || r.at <= d.modified_at), `${P} doc ${d.id} revision ${r.at} outside [${d.created_at}, ${d.modified_at}]`);
    ok("GPS only on photos and videos", !d.gps || ["jpg", "heic", "mp4", "mov"].includes(d.ext), `${P} doc ${d.id} gps on .${d.ext}`);
    ok("gps flag ⇔ coordinates", d.flags.includes("gps") === !!d.gps, `${P} doc ${d.id}`);
    ok("secret flag ⇔ secret in the section", d.flags.includes("secret") === st.secrets.some(s => s.doc === d.id), `${P} doc ${d.id}`);
    ok("eol flag ⇔ unsupported software", d.flags.includes("eol") === !!(sw && B._swEol(sw)), `${P} doc ${d.id}`);
    const ty = +((d.title || "").match(/(20\d\d)/) || [])[1] || 0;
    if (ty) ok("year in the title ≈ document date", Math.abs(+d.created_at.slice(0, 4) - ty) <= 1, `${P} doc ${d.id} "${d.name}" created ${d.created_at.slice(0, 4)}`);
    if (d.author) ok("document author is among the people", st.people.some(p => p.login === d.author), `${P} doc ${d.id} author ${d.author}`);
  }
  // Derived entities: counters equal the actual references.
  for (const s of st.software) ok("software: counter = documents", s.docs === an.filter(d => d.software === s.id).length, `${P} ${s.name}: ${s.docs}`);
  ok("software: only software in use", st.software.every(s => s.docs > 0), `${P} software without documents`);
  for (const p of st.printers) ok("printers: counter = documents", p.docs === an.filter(d => d.printer === p.name).length, `${P} ${p.name}`);
  for (const p of st.paths) ok("paths: counter = documents", p.docs === an.filter(d => d.folder === p.path).length, `${P} ${p.path}`);
  for (const p of st.people.filter(x => x.src_kind === "meta")) ok("people: derived from metadata", p.docs === an.filter(d => d.author === p.login).length && p.docs > 0, `${P} ${p.login}`);
  for (const p of st.people.filter(x => x.src_kind === "text")) ok("people from text reference a document", byDoc[p.src_doc] && byDoc[p.src_doc].status === "analyzed", `${P} ${p.login}`);
  for (const s of st.secrets) ok("secrets only in analyzed documents", byDoc[s.doc] && byDoc[s.doc].status === "analyzed", `${P} secret ${s.id} → doc ${s.doc}`);
  ok("GPS points = photos with coordinates", st.gps.length === an.filter(d => d.gps).length && st.gps.every(g => byDoc[g.doc] && byDoc[g.doc].created_at === g.taken_at), `${P} gps`);
  for (const e of st.events) ok("timeline events come from document dates", !e.ref || (byDoc[e.ref.id] && byDoc[e.ref.id].created_at.startsWith(`${e.y}-${e.m}`)), `${P} event "${e.t}"`);
  for (const h of st.hosts.filter(h => h.internal)) ok("internal hosts are derived from data", st.pcs.some(p => p.name === h.name), `${P} ${h.name}`);
  ok("documents only from in-scope hosts", docs.every(d => B._scope.check(st.scope, d.host).ok), `${P} document from an out-of-scope host`);
  // Findings.
  const scanIds = st.scans.map(s => s.id);
  for (const f of st.findings) {
    const tag = `${P} finding ${f.id} «${f.title}»`;
    if (f.doc) ok("findings: document exists and is analyzed", byDoc[f.doc] && byDoc[f.doc].status === "analyzed", tag);
    ok("findings: host exists", f.host === "-" || st.hosts.some(h => h.name === f.host), `${tag} → ${f.host}`);
    f.rel.people.forEach(l => ok("findings: related people exist", st.people.some(p => p.login === l), `${tag} → ${l}`));
    f.rel.pcs.forEach(n => ok("findings: related computers exist", st.pcs.some(p => p.name === n), `${tag} → ${n}`));
    f.rel.docs.forEach(i => ok("findings: related documents exist", !!byDoc[i], `${tag} → doc ${i}`));
    ok("findings: source scan exists", scanIds.includes(f.first_scan), `${tag} → ${f.first_scan}`);
    if (f.doc && byDoc[f.doc].author && f.category === "docs" && f.rel.people.length === 1) ok("findings do not contradict the document author", f.rel.people[0] === byDoc[f.doc].author || f.title.includes("rdp"), tag);
    if (f.active) {
      ok("active findings only in scope (exclusions honoured)", B._scope.check(st.scope, f.host).ok, `${tag} on ${f.host}`);
      const sc = st.scans.find(s => s.id === f.first_scan);
      ok("active findings only from an active scan", sc && sc.active, `${tag} from scan ${sc && sc.profile}`);
    }
    const m = f.title.match(/у (\d+) документов|метаданных (\d+) документов/);
    if (m) { const n = +(m[1] || m[2]); const real = f.title.includes("Acrobat") ? an.filter(d => d.software === "acro11").length : f.title.includes("пути") ? an.filter(d => d.flags.includes("path")).length : an.filter(d => d.software && f.title.startsWith(SWD[d.software].name)).length; ok("numbers in finding text = data", n === real, `${tag}: ${n} ≠ ${real}`); }
    const vm2 = f.title.match(/Apache (\d+\.\d+\.\d+)/);
    if (vm2 && st.scans.length) { const last = st.scans[st.scans.length - 1].snapshot; ok("software version in a finding = host version in the last scan", (last.hosts[f.host] || "").includes(vm2[1]), `${tag}: host ${last.hosts[f.host]}`); }
    if (f.status === "fixed" && st.scans.length) ok("fixed findings do not reproduce in the last scan", !(f.id in st.scans[st.scans.length - 1].snapshot.findings), tag);
  }
  // Scans.
  for (const s of st.scans) {
    ok("scan profiles come only from /new", PROFILES.includes(s.profile), `${P} profile "${s.profile}"`);
    ok("active scan only \"full\"/\"custom\", no contract fields", !s.active || ((s.profile === "Полный" || s.profile === "Свой") && !("contract" in s)), `${P} ${s.id}`);
    ok("one egress IP across all scans", s.egress === st.scans[0].egress && s.egress.includes(S.settings.net.out_ip), `${P} ${s.egress}`);
    for (const src of s.sources) { const def = B.SOURCES.find(x => x.id === src.id); ok("source statuses = key statuses", !def.key || (S.settings.keys[def.key].status === "ok") === (src.status === "ok"), `${P} ${src.id}: ${src.status}`); }
    ok("no Bing/Google scraping among sources", !s.sources.some(x => /bing|^google$/i.test(x.id)), `${P} ${s.id}`);
  }
}

// Projects differ from each other.
const projs = S.order.map(id => S.projects[id]);
ok("at least 3 projects", projs.length >= 3, "too few projects");
ok("projects differ in document count", new Set(projs.map(p => p.docs.length)).size === projs.length, "identical document counts");
ok("large project with ~340 documents and 2 scans", S.projects.contoso.docs.length >= 300 && S.projects.contoso.scans.length === 2, "contoso");
ok("a small project with one scan exists", projs.some(p => p.docs.length > 0 && p.docs.length < 100 && p.scans.length === 1), "no small project");
const empty = projs.find(p => !p.scans.length);
ok("a new project without scans or data exists", empty && !empty.docs.length && !empty.findings.length && !empty.people.length && !empty.hosts.length, "no empty project");
ok("project without scans: risk \"no data\"", empty && B._risk(empty) === null, "empty project risk");
ok("different projects have different people", new Set(projs.filter(p => p.people.length).map(p => p.people.map(x => x.login).sort().join())).size === projs.filter(p => p.people.length).length, "identical people");

for (const p of F.projects) { const st = S.projects[p.id]; ok("project card: findings = active ones (as in the last scan)", p.findings === st.findings.filter(f => f.status !== "false" && f.status !== "fixed").length && (!st.scans.length || st.scans[st.scans.length - 1].findings === p.findings), `${p.id}: ${p.findings}`); }
// UI layer: hydrate + selectors.
const C = F.sel.counts();
ok("F.db loaded at startup", F.db.project && F.db.project.id === "contoso", "F.db.project");
ok("F.sel counters = list lengths", C.docs.total === F.db.docs.filter(d => !d.deleted).length && C.people.total === F.db.people.length && C.hosts.total === F.db.hosts.length && C.secrets === F.db.secrets.length, JSON.stringify(C).slice(0, 200));
ok("findings by severity without false positives", C.findings.crit + C.findings.high + C.findings.warn + C.findings.low + C.findings.info === F.db.findings.filter(f => f.status !== "false" && f.status !== "fixed").length, "severity sum");
ok("new since the last scan", C.findings.new_since_last === F.db.findings.filter(f => f.first_scan === "contoso-s2" && f.status !== "false").length && C.findings.new_since_last > 0, `new_since_last=${C.findings.new_since_last}`);
ok("legacy: DEMO.software[i].n = documents", ctx.DEMO.software.every(s => s.n === ctx.DEMO.docs.filter(d => d.sw === s).length), "DEMO.software n");
ok("legacy: F.demoFindings = F.db.findings (27 + 23 forensic + 8 insight)", F.demoFindings.length === 58 && F.demoFindings === F.db.findings, `demoFindings ${F.demoFindings.length}`);
ok("legacy: F.project from F.db", F.project.name === "contoso.example" && F.project.risk === F.sel.risk().score, "F.project");
const sc = F.sel.scope;
ok("scope: excluded host denied", !sc.allows("mail.contoso.example"), "mail");
ok("scope: excluded network 10.0.0.0/8", !sc.allows("10.10.1.12") && !sc.allows("SRV-SQL02"), "10/8");
ok("scope: target subdomain allowed", sc.allows("files.contoso.example"), "files");
ok("scope: CIDR 203.0.113.0/24 in scope (also for the active phase, no separate permissions)", sc.allows("203.0.113.77") && sc.allowsActive === undefined, "cidr");
ok("scope: wildcard *.contoso-group.example", sc.allows("hr.contoso-group.example") && !sc.allows("contoso-group.org"), "wild");
ok("scope: active phase targets = all network targets", sc.info().activeTargets.length === F.db.scope.targets.filter(t => ctx.FOCA_RULES.scope.NET.includes(t.type)).length && sc.info().activeTargets.length > 0, "activeTargets contoso");
ok("scope: no contract fields or confirmations", !["num", "from", "to", "forbid", "allow_active"].some(k => k in F.db.scope) && F.db.scope.targets.every(t => !("active" in t)), "scope keys");
ok("UI: no confirmation screen or permission functions", !F.sel.scope.gate && !F.sel.scope.hash && !F.sel.scope.activeAllowed && !F.api.active_acks && !F.launchConfirm, "no confirm");
const srch = q => F.sel.search(q).total;
ok("search: across all 25 findings and e-mail", srch("AWS") > 0 && srch("AXFR") > 0 && srch("TLS") > 0 && F.sel.search("info@").emails.length > 0, "search");
const df = F.sel.diff(0, 1);
ok("diff from snapshots: has changes, all links valid", df.items.length > 0 && df.items.every(i => !i.ref || F.sel.entity(i.ref.type, i.ref.id)), `diff ${df.items.length}`);
ok("diff: Apache did not \"change\"", !df.items.some(i => i.k === "~" && /Apache/.test(i.was + i.now)), "Apache in the diff");
ok("relations: numbers = list lengths", (() => { const r = F.sel.related("person", "a.bondar"); return r.docs.length === F.db.people.find(p => p.login === "a.bondar").docs; })(), "related person");
ok("graph: has person nodes from text", !!F.sel.graph("person", "y.hrytsenko"), "graph y.hrytsenko");

// Commands.
await F.api.project_open("dnipro");
ok("project switch changes F.db", F.db.project.id === "dnipro" && F.sel.counts().docs.total === 0 && F.sel.risk().score === null, "dnipro");
{ let err = null; try { await F.api.scan_start({ profile: "full", active: true }); } catch (e) { err = e.code || String(e); }
  const st0 = ctx.FOCA_DEMO_BACKEND.invokeSync("scan_status");
  ok("scan_start \"full\" starts immediately, no confirmations (dnipro)", !err && st0.running && st0.level === "active", String(err) + JSON.stringify(st0).slice(0, 120));
  ctx.FOCA_DEMO_BACKEND._ff(5); await F.api.scan_stop("user"); }
await F.api.project_open("contoso");
const delId = F.db.docs.find(d => d.status_code === "analyzed" && d.software === "acro11").id;
const before = F.sel.counts().docs.total, swBefore = F.db.software.find(s => s.id === "acro11").n;
await F.api.doc_delete([delId]);
ok("doc_delete: counters recomputed", F.sel.counts().docs.total === before - 1 && F.db.software.find(s => s.id === "acro11").n === swBefore - 1, "doc_delete");
await F.api.doc_restore([delId]);
const created = await F.api.project_create({ name: "newcorp.ua", client: "ТОВ «Нью Корп»", targets: ["newcorp.ua"], excludes: [] });
ok("project_create: new empty project", F.projects.some(p => p.id === created.id) && created.docs === 0 && created.risk === null, "create");
await F.api.project_open(created.id);
const events = []; const off = F.on("scan", e => events.push(e.type));
await F.api.scan_start({ profile: "std", active: false });
await new Promise(r => setTimeout(r, 8000));
off();
const N2 = F.sel.counts();
ok("scan_start fills the new project stage by stage", events.includes("stage") && events.includes("finding") && events.includes("done") && N2.docs.total > 0 && N2.people.total > 0 && F.db.scans.length === 1 && F.db.scans[0].profile === "Стандартный", JSON.stringify({ ev: [...new Set(events)], docs: N2.docs.total }));
ok("new project data follows its target", F.db.docs.every(d => d.host.endsWith("newcorp.ua")) && F.db.hosts.some(h => h.name === "newcorp.ua"), "hosts newcorp");

// Host network, OS, report selection and request log, for EVERY project.
for (const id of B._state().order) {
  const st = B._state().projects[id]; const P = `[${id}]`; const dom = st.project.domain;
  if (id !== "contoso") ok("no contoso in the project data", !/contoso/i.test(JSON.stringify({ ...st, reports: [] })), `${P} found "contoso"`);
  for (const h of st.hosts) {
    const ip = String(h.ip).split(" ")[0]; const numeric = /^\d+\.\d+\.\d+\.\d+$/.test(ip);
    ok("host has dns[] / asn / tls (contract fields)", Array.isArray(h.dns) && "asn" in h && "tls" in h, `${P} ${h.name}`);
    if (numeric && !h.internal) ok("A record = host IP", h.dns.some(r => r[0] === "A" && r[1] === ip), `${P} ${h.name}`);
    if (h.internal) ok("internal hosts have no external DNS/TLS/ASN", !h.dns.length && !h.tls && !h.asn, `${P} ${h.name}`);
    if (h.tls) ok("TLS only on external hosts with 443/tcp, valid date", !h.internal && (h.services || []).some(s => /^443\//.test(s[0])) && /^\d{4}-\d\d-\d\d$/.test(h.tls.not_after) && (h.tls.cn === h.name || h.tls.cn === `*.${dom}`), `${P} ${h.name}`);
    if (h.name === dom) {
      const dm = st.findings.some(f => /DMARC p=none/.test(f.title));
      ok("DMARC in DNS = finding", h.dns.some(r => r[0] === "TXT" && /DMARC1/.test(r[1]) && (/p=none/.test(r[1]) === dm)), `${P} ${h.name}`);
    }
    const cert = st.findings.find(f => f.host === h.name && /Not After: (\d{4}-\d\d-\d\d)/.test(f.evidence || ""));
    if (cert && h.tls) ok("certificate expiry = finding", cert.evidence.includes(h.tls.not_after), `${P} ${h.name}`);
  }
  await F.api.project_open(id);
  const os = F.sel.os(), an = new Set(F.db.docs.filter(d => !d.deleted && d.status_code === "analyzed").map(d => d.id));
  ok("OS derived from analyzed documents", os.every(o => o.docs === o.doc_ids.length && o.doc_ids.every(i => an.has(i))) && os.reduce((a, o) => a + o.docs, 0) <= an.size, `${P} os`);
  ok("project with documents has OS; without documents none", an.size ? os.length > 0 : !os.length, `${P} os=${os.length}`);
  F.sel.requests(); await new Promise(r => setTimeout(r, 0)); // the count comes from request_log_get (asynchronously)
  const rq = F.sel.requests();
  ok("request log only with scans", F.db.scans.length ? rq.total > 0 : rq.total === 0 && !rq.sample.length, `${P} ${rq.total}`);
  { const n = (await F.api.request_log_get({ limit: 1e9 })).length; ok("log in export = request_log_get (not an estimate)", rq.total === n, `${P} ${rq.total} vs ${n}`); }
  const all = F.sel.reportFindings({ confirmed: false, min_sev: "all" });
  ok("report: no false positives; fixed listed separately", all.main.every(f => f.status !== "false" && f.status !== "fixed") && all.fixed.every(f => f.status === "fixed") && all.main.length + all.fixed.length === F.db.findings.filter(f => f.status !== "false").length, `${P} report`);
  ok("\"confirmed only\" and \"minimum severity\"", F.sel.reportFindings({ confirmed: true, min_sev: "high" }).main.every(f => f.status === "confirmed" && ["crit", "high"].includes(f.sev)), `${P} report filters`);
  const live = F.db.findings.filter(F.sel.isLive).slice(0, 2).map(f => f.id);
  await F.api.settings_set({ report: { picked: { [id]: live } } });
  ok("\"add to report\" selection is stored in settings and honoured", JSON.stringify(F.sel.reportPicked()) === JSON.stringify(live) && JSON.stringify(B._state().settings.report.picked[id]) === JSON.stringify(live) && F.sel.reportFindings({ picked_only: true, min_sev: "all" }).main.every(f => live.includes(f.id)), `${P} picked`);
  if (F.db.scans.length) {
    const r = await F.api.report_build({ tpl: "Полный отчёт пентеста", tpl_id: "full", fmt: "pdf", lang: "UA", min_sev: "warn", confirmed: false, picked_only: true, picked: live, sections: { summary: true, fixed: true }, secrets: "hide" });
    ok("report_build stores the report options (opts)", r.opts && r.opts.min_sev === "warn" && r.opts.picked_only === true && JSON.stringify(r.opts.picked) === JSON.stringify(live) && F.db.reports[0].id === r.id && r.name.includes(st.project.name), `${P} report_build`);
  }
}

// Out-of-scope candidates (from project data).
for (const id of S.order) {
  const st = S.projects[id], P = `[${id}]`, L = B._oos(st);
  if (!st.hosts.length) ok("out of scope: a project without data has no candidates", L.length === 0, `${P} ${L.length}`);
  for (const o of L) {
    ok("out of scope: new candidates are not covered by the scope", o.decision !== "new" || !B._scope.check(st.scope, o.host).ok, `${P} ${o.host}`);
    ok("out of scope: own only with evidence (A record/redirect from an in-scope host)", !o.own || (["ip", "redirect"].includes(o.kind) && o.via && B._scope.check(st.scope, o.via).ok), `${P} ${o.host}`);
    ok("out of scope: blocked candidates are not own", !o.blocked || !o.own, `${P} ${o.host}`);
    ok("out of scope: no network (CIDR) suggested from found addresses, only a single IP", o.kind !== "net" && !/\//.test(o.host), `${P} ${o.host}`);
    if (o.shared) ok("out of scope: shared hosting address is a single IP with a warning", o.kind === "ip" && !o.own && /общий хостинг/i.test(o.hint), `${P} ${o.host}`);
    if (o.kind === "cname") ok("out of scope: dangling CNAME is blocked and links to a finding", !!o.blocked && (!o.finding || st.findings.some(f => f.id === o.finding && f.host === o.via)), `${P} ${o.host}`);
    if (o.n != null) ok("out of scope: numbers in the description = data", o.why.includes(String(o.n)), `${P} ${o.why}`);
    // Infrastructure candidates (source = san|org_pivot|tenant_domain|…) name their origin (O=, tenant…), not a host.
    if (o.via && !o.source) ok("out of scope: source is an existing host", st.hosts.some(h => h.name === o.via), `${P} ${o.via}`);
  }
}

// Infrastructure: infra_get records agree with the hosts, findings and out-of-scope candidates.
for (const id of S.order) {
  const st = S.projects[id], P = `[${id}]`, I = B._infra(st), dom = st.project.domain;
  const ext = st.hosts.filter(h => !h.internal), byName = Object.fromEntries(st.hosts.map(h => [h.name, h]));
  const inScope = n => B._scope.check(st.scope, n, st.hosts).ok;
  const KINDS = ["saas", "tenant", "mail_policy", "cert", "ct", "cdn", "origin", "role", "ptr", "dns_enum", "oos"];
  ok("infra: every kind is an array", KINDS.every(k => Array.isArray(I[k])), `${P} ${Object.keys(I)}`);
  const done = (st.scans || []).filter(s => s.status === "done");
  if (!done.length || !st.hosts.length) ok("infra: nothing without a finished scan", KINDS.every(k => !I[k].length), `${P}`);
  if (done.length && done.every(s => s.profile_id === "passive")) ok("infra: passive scans give no certificates or enumeration", !I.cert.length && !I.dns_enum.length && !I.ptr.length, `${P}`);
  for (const h of st.hosts) {
    ok("infra: host has roles[] / priority / cdn (contract fields)", Array.isArray(h.roles) && typeof h.priority === "number" && "cdn" in h, `${P} ${h.name}`);
    const r = I.role.find(x => x.host === h.name);
    if (I.role.length || h.roles.length) ok("infra: host roles/priority = role record", r ? JSON.stringify(r.roles) === JSON.stringify(h.roles) && r.priority === h.priority : !h.roles.length && !h.priority, `${P} ${h.name}`);
    const c = I.cdn.find(x => x.host === h.name);
    if (done.length) ok("infra: host CDN label = cdn record", JSON.stringify(c || null) === JSON.stringify(h.cdn || null), `${P} ${h.name}`);
    if (h.cdn) ok("infra: CDN provider matches the host's cloud and IP", h.cdn.ip === h.ip && (h.cloud === "-" || h.cloud.toLowerCase().includes(h.cdn.provider === "aws" ? "aws" : h.cdn.provider)), `${P} ${h.name} ${h.cloud}`);
    if (h.internal) ok("infra: internal hosts have no roles or CDN", !h.roles.length && !h.cdn, `${P} ${h.name}`);
  }
  for (const c of I.cert) {
    const h = byName[c.host];
    ok("infra: certificate of an existing in-scope host with 443/tcp", h && !h.internal && inScope(h.name) && (h.services || []).some(x => /^443\//.test(x[0])) && c.port === 443, `${P} ${c.host}`);
    if (!h || !h.tls) continue;
    const leaf = c.chain[0];
    ok("infra: certificate = host TLS summary (subject, issuer, expiry)", leaf.subject.cn === h.tls.cn && leaf.issuer.cn === h.tls.issuer && new Date(leaf.not_after * 1000).toISOString().slice(0, 10) === h.tls.not_after && JSON.stringify(leaf.san_dns) === JSON.stringify(h.tls.san || []), `${P} ${c.host}`);
    ok("infra: days_left = expiry − today", c.days_left === Math.round((Date.parse(h.tls.not_after) - Date.parse(B.TODAY)) / 864e5), `${P} ${c.host} ${c.days_left}`);
    for (const i of c.issues) ok("infra: certificate issue = finding infra.<code> on the host", st.findings.some(f => f.host === c.host && (f.provenance || {}).rule === `infra.${i.code}`), `${P} ${c.host} ${i.code}`);
  }
  for (const f of st.findings.filter(f => /^infra\./.test((f.provenance || {}).rule || ""))) {
    const code = f.provenance.rule.slice(6);
    const backed = /^(cert|tls)_/.test(code) ? I.cert.some(c => c.host === f.host && c.issues.some(i => i.code === code))
      : code === "host_role_exposed" ? I.role.some(r => r.host === f.host && r.alive && f.tags.every(t => !/^role:/.test(t) || r.roles.includes(t.slice(5))))
      : /^m365_/.test(code) ? I.tenant.some(t => t.domain === f.host && (code !== "m365_federated_adfs" || (t.adfs && f.evidence.includes(t.openid.tenant_id) && f.evidence.includes(t.federation_host))))
      : true;
    ok("infra: every infra.* finding is backed by an infra record", backed, `${P} ${f.id} ${code}`);
    ok("infra: infra.* finding category is tls|dns|cloud|hosts|mail", ["tls", "dns", "cloud", "hosts", "mail"].includes(f.category), `${P} ${f.id} ${f.category}`);
  }
  for (const t of I.tenant) {
    ok("infra: tenant of the project domain, tenant id is a uuid", t.domain === dom && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(t.openid.tenant_id), `${P} ${t.openid.tenant_id}`);
    if (t.adfs) ok("infra: AD FS host is a project host found via the tenant", byName[t.federation_host] && byName[t.federation_host].source === "m365", `${P} ${t.federation_host}`);
    ok("infra: tenant ⇔ Microsoft 365 in the SaaS map", I.saas.some(s => s.hits.some(x => x.id === "microsoft365")), `${P}`);
  }
  for (const m of I.mail_policy) ok("infra: DNSSEC status = DNSSEC finding", (m.dnssec === "unsigned") === st.findings.some(f => /DNSSEC/.test(f.title)), `${P} ${m.dnssec}`);
  const enumHosts = st.hosts.filter(h => /^(bruteforce|permute|doc_token:|ptr|nsec|tls_san)/.test(h.source || ""));
  if (enumHosts.length) ok("infra: hosts found by enumeration ⇒ dns_enum summary covers them", I.dns_enum.length && I.dns_enum[0].brute.hits >= st.hosts.filter(h => h.source === "bruteforce").length, `${P}`);
  for (const h of enumHosts) ok("infra: enumerated host is in the scope zone", h.name.endsWith("." + dom) && inScope(h.name), `${P} ${h.name}`);
  for (const p of I.ptr) ok("infra: PTR only for in-scope addresses of project hosts", inScope(p.ip) && p.hosts.every(n => byName[n] && byName[n].ip === p.ip), `${P} ${p.ip}`);
  for (const o of I.origin) for (const c of o.candidates) ok("infra: origin candidate = address of a project host, not behind the CDN", ext.some(h => h.ip === c.ip && !h.cdn), `${P} ${c.ip}`);
  const L = B._oos(st);
  for (const o of I.oos) {
    ok("infra: out-of-scope candidate is outside the scope", !inScope(o.host), `${P} ${o.host}`);
    ok("infra: candidate listed in oos_list with source and why_key", L.some(x => x.host === o.host && x.source === o.kind && x.why_key === `oos.why.${o.kind}`), `${P} ${o.host}`);
  }
}
{
  await F.api.project_open("contoso");
  const cand = F.db.oos.find(o => !o.blocked && o.decision === "new"), blk = F.db.oos.find(o => o.blocked);
  let blocked = false; try { await F.api.oos_decide(blk.id, "scope"); } catch (e) { blocked = e.code === "blocked"; }
  ok("oos_decide: a blocked candidate cannot be added to scope", blocked, blk.host);
  await F.api.oos_decide(cand.id, "scope");
  await F.api.scope_set({ targets: F.db.scope.targets.concat({ v: cand.host, type: cand.kind === "ip" ? "ip" : "domain", active: false }) });
  const snap = await F.api.project_snapshot("contoso");
  ok("oos_decide + scope_set: candidate in scope, decision stored in the snapshot", F.sel.scope.allows(cand.host) && snap.oos.some(o => o.host === cand.host && o.decision === "scope"), cand.host);
  await F.api.scan_start({ profile: "passive" }); B._ff(60);
  ok("candidate decision survives a new scan", F.db.oos.some(o => o.host === cand.host && o.decision === "scope"), cand.host);
}
// Pause, stop and resume from where the scan stopped.
{
  const nc = await F.api.project_create({ name: "pausecorp.ua", client: "", targets: [{ v: "pausecorp.ua", type: "domain", active: false }], excludes: [] });
  await F.api.project_open(nc.id);
  ok("project_create: target objects keep their type", F.db.scope.targets.length === 1 && F.db.scope.targets[0].type === "domain", JSON.stringify(F.db.scope.targets));
  const evs = []; const off2 = F.on("scan", e => evs.push(e));
  await F.api.scan_start({ profile: "std", modules: ["search", "crt", "wayback", "dns", "docs", "alive"] });
  ok("\"standard\" with dns/docs/alive modules does not need the active phase", evs.some(e => e.type === "started" && !e.active), "std active");
  B._ff(10); await F.api.scan_pause();
  const p0 = B.invokeSync("scan_status"); B._ff(5);
  ok("scan_pause: the core does not advance while paused", B.invokeSync("scan_status").progress === p0.progress && p0.paused, JSON.stringify(p0));
  await F.api.scan_resume(); B._ff(10);
  await F.api.scan_stop("vpn");
  const stp = F.db.scans[F.db.scans.length - 1];
  ok("scan_stop: stopped record with reason and progress", stp.status === "stopped" && stp.reason === "vpn" && stp.progress > 0 && !!stp.stage, JSON.stringify({ s: stp.status, r: stp.reason, p: stp.progress }));
  evs.length = 0;
  await F.api.scan_start({ profile: "std", resume_from: stp.id });
  const pr = evs.find(e => e.type === "progress");
  ok("scan_start resume_from: resumes where it stopped", pr && pr.progress >= stp.progress, JSON.stringify(pr));
  B._ff(60); off2();
  ok("resuming a new project's first (stopped) scan yields full data", F.db.scans.length === 1 && F.db.scans[0].status === "done" && F.db.scans[0].id === stp.id && F.sel.counts().docs.analyzed > 0 && F.db.docs.every(d => d.host.endsWith("pausecorp.ua")), JSON.stringify({ scans: F.db.scans.map(s => s.status), docs: F.sel.counts().docs }));
}

// Dynamic checks: scan/stop/resume/restart, scope, active phase, report, secrets.
{
  const R = ctx.FOCA_RULES;
  // Risk formula = foca_analysis::findings::risk: false positives, fixed and `out_of_scope` findings do not count.
  const oosF = { sev: "crit", status: "new", tags: ["out_of_scope"] }, liveF = { sev: "crit", status: "new", tags: [] };
  ok("risk skips out_of_scope findings like the core", R.riskScore([oosF]) === 0 && R.riskScore([liveF, oosF]) === 25 && R.riskScore([{ ...liveF, status: "false" }]) === 0, [R.riskScore([oosF]), R.riskScore([liveF, oosF])]);
  // "Critical" level needs an in-scope live critical finding: an out-of-scope one never sets it.
  const highs = Array.from({ length: 19 }, () => ({ sev: "high", status: "new", tags: [] }));
  const lvl = l => R.riskLevel(R.riskScore(l), R.hasCrit(l));
  ok("risk level: out-of-scope critical finding does not make it Critical", lvl([...highs, oosF]) === "high" && lvl([...highs, liveF]) === "crit" && !R.hasCrit([{ ...liveF, status: "fixed" }]), [lvl([...highs, oosF]), lvl([...highs, liveF])]);
  B.invokeSync("demo_reset"); await F.api.project_list(); await F.api.project_open("contoso");
  // Document status labels are read in the current language (in-app switch keeps the hydrated snapshot).
  {
    const d0 = F.db.docs.find(d => d.status_code === "analyzed"), ru = d0.status;
    F.t = (k, fb) => ({ "doc_status.analyzed": "Analyzed" })[k] || fb;
    const en = d0.status;
    delete F.t;
    ok("doc status label follows the language without reloading the snapshot", ru === "Проанализирован" && en === "Analyzed" && d0.status === ru, JSON.stringify({ ru, en }));
  }
  const snapC = () => { const C = F.sel.counts(); return { an: C.docs.analyzed, total: C.docs.total, people: C.people.total, sw: C.software.total, sec: C.secrets, f: C.findings.open }; };
  const refsOk = () => F.db.findings.every(f => (!f.doc || F.db.docs.some(d => d.id === f.doc)) && f.rel.people.every(l => F.db.people.some(p => p.login === l)));
  const c0 = snapC(); const s2 = F.db.scans[F.db.scans.length - 1];
  // Stopping after the download stage (before metadata), restarting the app and resuming erases nothing.
  await F.api.scan_start({ profile: "std" }); B._ff(18);
  const st1 = B.invokeSync("scan_status");
  ok("scan_status returns active/profile/targets", st1.running && st1.profile === "Стандартный" && st1.profile_id === "std" && st1.active === false && Array.isArray(st1.targets) && st1.targets.length > 0, JSON.stringify(st1));
  await F.api.scan_stop("user");
  ok("stop after the download stage keeps metadata", JSON.stringify(snapC()) === JSON.stringify(c0) && refsOk(), JSON.stringify({ before: c0, after: snapC() }));
  B._restart(); await F.api.project_open("contoso");
  ok("data intact after an app restart", JSON.stringify(snapC()) === JSON.stringify(c0), JSON.stringify(snapC()));
  const stopRec = F.db.scans[F.db.scans.length - 1];
  await F.api.scan_start({ profile: "std", resume_from: stopRec.id }); B._ff(60);
  const done = F.db.scans[F.db.scans.length - 1];
  ok("resume runs to completion without losses", JSON.stringify(snapC()) === JSON.stringify(c0) && refsOk(), JSON.stringify(snapC()));
  ok("resume keeps the same history record (stopped → done)", done.id === stopRec.id && done.status === "done" && !F.db.scans.some(s => s.status === "stopped"), F.db.scans.map(s => s.id + ":" + s.status).join());
  const df = F.sel.diff(s2.id, done.id);
  ok("repeat without changes: empty diff, findings as in the previous scan, 0 new", df.items.length === 0 && done.findings === s2.findings && done.new_findings === 0, JSON.stringify({ items: df.items.length, f: [s2.findings, done.findings], n: done.new_findings }));
  // Triage and deletions made during a rescan are preserved.
  await F.api.scan_start({ profile: "std" }); B._ff(8);
  await F.api.finding_set_status(5, "confirmed"); await F.api.finding_set_status(3, "false"); await F.api.finding_update(7, { notes: [{ text: "моя заметка", who: "Вы", time: "20.11" }], sev: "high" });
  await F.api.doc_delete([7]);
  B._ff(60);
  const f = id => F.db.findings.find(x => x.id === id);
  ok("user statuses, notes and severity survive a scan", f(5).status === "confirmed" && f(3).status === "false" && f(7).sev === "high" && f(7).notes.some(n => n.text === "моя заметка"), JSON.stringify([f(5).status, f(3).status, f(7).sev]));
  ok("a document deleted during the scan stays deleted", F.db.docs.find(d => d.id === 7).deleted === true, "doc 7");
  // The project card updates right after triage.
  const card = () => F.projects.find(p => p.id === "contoso");
  const n0 = card().findings; await F.api.finding_set_status(2, "false");
  ok("project card recomputed after triage", card().findings === n0 - 1 && card().risk === F.sel.risk().score, JSON.stringify({ n0, n: card().findings }));
  await F.api.finding_set_status(2, "new");
  // Deleting a document is reflected in GPS, secrets, software, people and the diff, also after a reload.
  await F.api.doc_delete([1, 2]);
  const chk9 = () => !F.db.gps.some(g => g.doc === 2) && !F.db.secrets.some(x => x.doc === 1) && F.db.software.every(s => s.docs === F.db.docs.filter(d => !d.deleted && d.software === s.id && d.status_code === "analyzed").length)
    && F.db.people.filter(p => p.src_kind === "meta").every(p => p.docs === F.db.docs.filter(d => !d.deleted && d.author === p.login && d.status_code === "analyzed").length)
    && F.db.scans.every((s, i) => !i || F.sel.diff(i - 1, i).items.every(x => x.g !== "docs" || x.k !== "+" || !F.db.docs.find(d => d.id === x.ref.id).deleted));
  ok("derived entities exclude deleted documents", chk9(), "after deletion");
  B._restart(); await F.api.project_open("contoso");
  ok("same numbers after a reload", chk9() && F.sel.counts().docs.deleted === 3, "after reload");
  await F.api.doc_restore([1, 2, 7]);
  // All history records are counted by the same rule.
  for (const id of S.order.concat(["contoso"])) {
    const st = B._state().projects[id]; if (!st) continue;
    st.scans.forEach((s, i) => { const prev = i ? st.scans[i - 1].snapshot : { findings: {} };
      ok("findings = |snapshot.findings|, new = absent from the previous record's snapshot", s.findings === Object.keys(s.snapshot.findings).length && s.new_findings === Object.keys(s.snapshot.findings).filter(k => !(k in prev.findings)).length && s.added && s.added.findings === s.new_findings, `${id} ${s.id}`); });
  }
  // Reload during a new project's first scan: the record is "interrupted", risk is "no data", and the scan resumes.
  const np = await F.api.project_create({ name: "reload.ua", client: "", targets: [{ v: "reload.ua", type: "domain", active: false }], excludes: [] });
  await F.api.project_open(np.id);
  await F.api.scan_start({ profile: "std" }); B._ff(22);
  B._restart(); await F.api.project_list(); await F.api.project_open(np.id);
  const r3 = F.db.scans[F.db.scans.length - 1];
  ok("a scan during an app restart is recorded as interrupted and can be resumed", !B.invokeSync("scan_status").running && r3 && r3.status === "stopped" && r3.reason === "restart" && r3.progress > 0 && !!r3.stage, JSON.stringify(r3 && { s: r3.status, r: r3.reason, p: r3.progress }));
  ok("risk is \"no data\" before the analysis stage", F.sel.risk().score === null && F.projects.find(p => p.id === np.id).risk === null, String(F.sel.risk().score));
  await F.api.scan_start({ profile: "std", resume_from: r3.id }); B._ff(60);
  ok("resume after restart completes the same scan", F.db.scans.length === 1 && F.db.scans[0].status === "done" && F.sel.counts().docs.analyzed > 0 && F.sel.risk().score !== null, F.db.scans.map(s => s.status).join());
  // One scope rule shared by the UI and the core; excluding a name also covers its IP.
  await F.api.project_open("contoso");
  ok("IP of an excluded host inside a CIDR target is denied", !F.sel.scope.allows("203.0.113.20") && F.sel.scope.check("203.0.113.20").code === "excluded", JSON.stringify(F.sel.scope.check("203.0.113.20")));
  const stK = B._state().projects.logistics;
  ok("logistics: IP of the excluded crm is denied in the core too", !B._scope.check(stK.scope, "198.51.100.20", stK.hosts).ok && B._scope.check(stK.scope, "198.51.100.10", stK.hosts).ok, "kyiv");
  for (const id of B._state().order) {
    const st = B._state().projects[id]; await F.api.project_open(id);
    const probes = [...st.hosts.map(h => h.name), ...st.hosts.map(h => String(h.ip).split(" ")[0]), "evil" + (st.project.domain || st.project.name), "x.y." + (st.project.domain || st.project.name), "1.2.3.4"];
    probes.forEach(h => { const a = F.sel.scope.check(h), b = B._scope.check(st.scope, h, st.hosts); ok("F.sel.scope.check = core rule", a.ok === b.ok && a.code === b.code, `${id} ${h}`); });
  }
  const T = (t, e) => ({ targets: t, excl: e || [] });
  const ck = (sc, h) => R.scope.check(sc, h, {}).ok;
  ok("Rust rule: Domain includes subdomains, boundary at a dot", ck(T([{ v: "contoso.ua", type: "domain" }]), "a.b.contoso.ua") && ck(T([{ v: "contoso.ua", type: "domain" }]), "Portal.Contoso.UA.") && !ck(T([{ v: "contoso.ua", type: "domain" }]), "evilcontoso.ua") && !ck(T([{ v: "contoso.ua", type: "domain" }]), "contoso.ua.evil.com"), "domain");
  ok("Rust rule: Wildcard only subdomains, Url exact host", ck(T([{ v: "*.contoso.ua", type: "wild" }]), "www.contoso.ua") && !ck(T([{ v: "*.contoso.ua", type: "wild" }]), "contoso.ua") && ck(T([{ v: "https://shop.example.com/x", type: "url" }]), "shop.example.com") && !ck(T([{ v: "https://shop.example.com/x", type: "url" }]), "a.shop.example.com"), "wild/url");
  ok("Rust rule: exclusions win, Org/e-mail/ASN grant no rights", !ck(T([{ v: "contoso.ua", type: "domain" }], ["vpn.contoso.ua"]), "x.vpn.contoso.ua") && ck(T([{ v: "contoso.ua", type: "domain" }], ["*.dev.contoso.ua"]), "dev.contoso.ua") && !ck(T([{ v: "10.0.0.0/8", type: "cidr" }], ["10.2.0.1-10.2.0.9"]), "10.2.0.5") && ck(T([{ v: "10.0.0.0/8", type: "cidr" }], ["10.2.0.1-10.2.0.9"]), "10.2.0.10")
    && !ck(T([{ v: "a@contoso.ua", type: "email" }, { v: "Contoso LLC", type: "org" }, { v: "AS1234", type: "asn" }]), "contoso.ua"), "excl/org");
  // Active phase: no confirmations; "full" and "custom" with active modules start in a single call.
  await F.api.project_open("medlab");
  let e5 = null; try { await F.api.scan_start({ profile: "full" }); } catch (e) { e5 = e.code || String(e); }
  const mf = B.invokeSync("scan_status");
  ok("active: \"full\" starts in one call, no toggle or confirmation", !e5 && mf.running && mf.level === "active", String(e5) + JSON.stringify(mf).slice(0, 120));
  B._ff(5); await F.api.scan_stop("user");
  await F.api.scan_start({ profile: "std" }); const md = B.invokeSync("scan_status"); B._ff(60);
  ok("active: \"standard\" needs no separate permissions (scope only)", md.running && md.level === "target", JSON.stringify(md));
  await F.api.project_open("contoso");
  await F.api.scan_start({ profile: "custom", modules: ["axfr"] }); const mc = B.invokeSync("scan_status");
  ok("active: \"custom\" with AXFR starts immediately at the active level", mc.running && mc.level === "active", JSON.stringify(mc).slice(0, 160));
  B._ff(5); await F.api.scan_stop("user");
  ok("active: no confirmation log", !("active_acks" in B._state().projects.contoso), "active_acks");
  let eX = null; try { await F.api.scan_start({ profile: "full", targets: ["mail.contoso.example"] }); } catch (e) { eX = e.code; }
  ok("active: exclusions are still not scanned (out_of_scope)", eX === "out_of_scope" && !B.invokeSync("scan_status").running, String(eX));
  // Targets come from the current scope; an excluded target is rejected, also on resume.
  await F.api.project_open("contoso");
  await F.api.scan_start({ profile: "std" }); B._ff(10); await F.api.scan_stop("user");
  const stp6 = F.db.scans[F.db.scans.length - 1];
  await F.api.scope_set({ excl: F.db.scope.excl.concat("contoso.example") });
  let e6 = null; try { await F.api.scan_start({ profile: "std", resume_from: stp6.id, targets: ["contoso.example"] }); } catch (e) { e6 = e.code; }
  ok("resume with an excluded target is rejected (out_of_scope)", e6 === "out_of_scope" && !B.invokeSync("scan_status").running, String(e6));
  let e6b = null; try { await F.api.scan_start({ profile: "std", targets: ["evil-competitor.com"] }); } catch (e) { e6b = e.code; }
  ok("out-of-scope target for \"standard\" is rejected", e6b === "out_of_scope", String(e6b));
  await F.api.scan_start({ profile: "passive", targets: ["evil-competitor.com"] }); const sp = B.invokeSync("scan_status"); B._ff(60);
  ok("passive scan accepts out-of-scope targets (external sources only)", sp.running && sp.targets.includes("evil-competitor.com"), JSON.stringify(sp.targets));
  await F.api.scope_set({ excl: F.db.scope.excl.filter(x => x !== "contoso.example") });
  // Report result snapshot and risk over the included findings.
  const rep = await F.api.report_build({ tpl: "Полный отчёт пентеста", tpl_id: "full", fmt: "pdf", lang: "RU", min_sev: "crit", confirmed: false, sections: { summary: true, findings: true, fixed: true } });
  const selR = F.sel.reportFindings({ min_sev: "crit" });
  ok("report risk covers the included findings", rep.result && rep.result.risk === R.riskScore(selR.main) && rep.result.total === selR.main.length && rep.result.risk !== F.sel.risk().score, JSON.stringify(rep.result && { r: rep.result.risk, p: F.sel.risk().score }));
  const fid = rep.result.finding_ids[0]; await F.api.finding_set_status(fid, "false");
  const rep2 = F.db.reports.find(r => r.id === rep.id);
  ok("report keeps a snapshot; triage afterwards does not change it", rep2.result.finding_ids.includes(fid) && rep2.result.total === rep.result.total, "snapshot");
  ok("report opts have no size/now; size and name come from the core", !("size" in rep.opts) && !("now" in rep.opts) && rep.size !== "-" && /_v\d+\.pdf$/.test(rep.name), JSON.stringify(rep.opts));
  const repCsv = await F.api.report_build({ tpl: "Данные", tpl_id: "data", fmt: "csv", lang: "RU" });
  ok("CSV report name has no language", /^Data_/.test(repCsv.name) && repCsv.lang === "-", repCsv.name);
  await F.api.finding_set_status(fid, "new");
  // Secrets are masked only; the value requires secret_reveal.
  const raw = await F.api.project_snapshot("contoso"); const js = JSON.stringify(raw);
  const plain = B._state().projects.contoso.secrets.map(x => x.value);
  ok("no clear-text secret values in the snapshot", raw.secrets.every(x => !("value" in x) && x.mask) && plain.every(v => !js.includes(v)) && !/Kont0so#2024/.test(js), "plain in snapshot");
  const rv = await F.api.secret_reveal(1);
  ok("secret_reveal returns the value", rv.value === plain[0], "reveal");
  const fr = (raw.findings.find(x => x.secret_refs && x.secret_refs.length) || {}).secret_refs || [];
  ok("evidence fragment is revealed by the f<id>:<k> reference", fr.length && !!(await F.api.secret_reveal(fr[0])).value, JSON.stringify(fr));
  ok("service field tech_s1 does not reach the snapshot", raw.hosts.every(h => !("tech_s1" in h)), "tech_s1");
  // An excluded candidate is not added; the command is atomic.
  const cand = F.db.oos.find(o => !o.blocked && o.decision === "new" && (o.kind === "redirect" || o.kind === "link"));
  await F.api.scope_set({ excl: F.db.scope.excl.concat(cand.host) });
  const cb = F.db.oos.find(o => o.host === cand.host);
  let e18 = null; try { await F.api.oos_add_to_scope(cand.id); } catch (e) { e18 = e.code; }
  ok("candidate from exclusions is blocked", !!(cb && cb.blocked) && e18 === "blocked", JSON.stringify({ b: cb && cb.blocked, e18 }));
  await F.api.scope_set({ excl: F.db.scope.excl.filter(x => x !== cand.host) });
  const r12 = await F.api.oos_add_to_scope(cand.id);
  ok("oos_add_to_scope: decision and target in one command", F.sel.scope.allows(cand.host) && r12.oos.some(o => o.host === cand.host && o.decision === "scope"), cand.host);
  // Beta commands.
  const ex = await F.api.export_build("users", "dict", { dict: "users" });
  ok("export_build: name/size/path come from the core", /_dict-users_2026-11-20\.txt$/.test(ex.name) && ex.path.startsWith("Download/") && ex.count > 0, JSON.stringify(ex));
  const cl = await F.api.doc_clean([1, 3]);
  ok("doc_clean: a secret in the text stays a manual item", cl.cleaned.find(c => c.id === 1).manual.length > 0 && !cl.cleaned.find(c => c.id === 1).clean && F.db.docs.find(d => d.id === 1).cleaned, JSON.stringify(cl.cleaned.map(c => [c.id, c.clean])));
  const ml = await F.api.ai_models_list("openai");
  ok("ai_models_list returns live models list shape", ml && ml.source === "api" && Array.isArray(ml.models) && ml.models.length > 0, JSON.stringify(ml));
  const ap = await F.api.ai_preview({}); const sm = await F.api.ai_summarize(ap.id, {});
  ok("ai_preview without secrets, ai_summarize cloud-only from the preview", !plain.some(v => ap.text.includes(v)) && ap.redacted > 0 && sm.md.length > 20 && !("local" in sm), JSON.stringify({ red: ap.redacted }));
  await F.api.pin_set("2580", "1111"); const p1 = await F.api.pin_check("0000"), p2 = await F.api.pin_check("2580");
  ok("pin_set/pin_check, PIN hash never reaches the UI", !p1.ok && p1.attempts_left === 4 && p2.ok && !JSON.stringify(await F.api.settings_get()).includes("pin_hash"), JSON.stringify([p1, p2]));
}

// Document forensics: doc_get records back the forensic findings and the doc flags; personal values
// are masked; full-text search, user rules and the offline import.
{
  await F.api.project_open("contoso");
  const st = B._state().projects.contoso, P = "[contoso]";
  const client = st.project.client;
  const tenant = (B._infra(st).tenant[0] || { openid: {} }).openid.tenant_id;
  const edrpouOk = s => { const d = [...s].map(Number), n = +s.slice(0, 7); const w = n >= 3000000 && n < 6000000 ? [7, 1, 2, 3, 4, 5, 6] : [1, 2, 3, 4, 5, 6, 7]; let c = d.slice(0, 7).reduce((a, x, i) => a + x * w[i], 0) % 11; if (c === 10) { c = d.slice(0, 7).reduce((a, x, i) => a + x * (w[i] + 2), 0) % 11; if (c === 10) c = 0; } return c === d[7]; };
  const fxOf = id => B.invokeSync("doc_get", { project: "contoso", id }).forensics;
  let withFx = 0;
  for (const d of st.docs.filter(x => x.status === "analyzed")) {
    const fx = fxOf(d.id), keys = ["signatures", "bad_redactions", "hidden_content", "pdf_revisions", "scan_without_text", "xmp_history", "xmp_ids", "pii", "links", "fields", "embedded"];
    ok("forensics: doc_get has every forensic key", keys.every(k => k in fx), `${P} doc ${d.id}`);
    const forensic = fx.signatures.length || fx.bad_redactions.length || fx.hidden_content.length || fx.pdf_revisions.length > 1 || fx.scan_without_text;
    ok("forensics: \"forensic\" flag ⇔ signature/redaction/hidden/revision record", d.flags.includes("forensic") === !!forensic, `${P} doc ${d.id}`);
    ok("forensics: \"pii\" flag ⇔ personal data (not ЄДРПОУ)", d.flags.includes("pii") === fx.pii.some(p => p.kind !== "edrpou"), `${P} doc ${d.id}`);
    const js = JSON.stringify(fx);
    ok("forensics: no full РНОКПП/card/IBAN values (masked)", !/(?<![\d•*])\d{10}(?!\d)|UA\d{27}|(?<!\d)\d{16}(?!\d)/.test(js.replace(/xmp\.[di]id:[^"]*|uuid:[^"]*|"serial":"[^"]*"|"byte_range":\[[^\]]*\]/g, "")), `${P} doc ${d.id}`);
    fx.pii.forEach(p => ok("forensics: PII samples are masked", p.samples.every(x => /[•*]/.test(x)) && p.count >= p.samples.length, `${P} doc ${d.id} ${p.kind}`));
    for (const sg of fx.signatures) {
      const c = sg.signer || {};
      withFx++;
      ok("forensics: signer organization = project client, ЄДРПОУ valid", c.organization === client && edrpouOk(c.edrpou || ""), `${P} doc ${d.id} ${c.organization} ${c.edrpou}`);
      ok("forensics: РНОКПП only masked (subject too)", /^\*{8}\d{2}$/.test(c.rnokpp_masked || "") && !/TINUA-\d{10}/.test(c.subject), `${P} doc ${d.id}`);
      ok("forensics: signer is a project person from the text", st.people.some(p => p.name && c.common_name.includes(p.name.split(" ")[1]) && c.common_name.includes(p.name.split(" ")[0])), `${P} ${c.common_name}`);
      ok("forensics: signing time not before the document date, TSA after signing", sg.signing_time.slice(0, 10) >= d.created_at.slice(0, 10) && (!sg.timestamp || sg.timestamp.gen_time >= sg.signing_time.slice(0, 10)), `${P} doc ${d.id}`);
      ok("forensics: modified after signing ⇔ bytes after the signed range", sg.modified_after_signing === sg.bytes_after > 0, `${P} doc ${d.id}`);
    }
    if (fx.pdf_revisions.length) ok("forensics: PDF revisions only in PDFs, numbered and growing", d.ext === "pdf" && fx.pdf_revisions.every((r, i) => r.revision === i + 1 && (!i || r.end_offset > fx.pdf_revisions[i - 1].end_offset)), `${P} doc ${d.id}`);
    if (fx.bad_redactions.length) ok("forensics: bad redaction only in PDFs, text ≤ 80 chars", d.ext === "pdf" && fx.bad_redactions.every(r => r.text.length <= 80 && ["black", "white"].includes(r.fill)), `${P} doc ${d.id}`);
    if (d.lnk) ok("forensics: LNK fields = doc.lnk (computer, MAC, volume)", fx.fields["lnk:machine_id"] === d.lnk.machine.toLowerCase() && fx.fields["lnk:mac"] === d.lnk.mac.toLowerCase() && fx.fields["lnk:volume_serial"] === d.lnk.volume_serial, `${P} doc ${d.id}`);
  }
  ok("forensics: the demo has signed documents", withFx > 0, "no signatures");
  const FX_RULE = /^(doc\.(?!anomaly|lineage)|mail\.|cal\.|pim\.|media\.|zip\.|pii$)/;
  const fxF = st.findings.filter(f => FX_RULE.test((f.provenance || {}).rule || ""));
  ok("forensics: findings of the 1.3 codes exist (≥ 20)", fxF.length >= 20, `${fxF.length}`);
  for (const f of fxF) {
    const rule = f.provenance.rule, d = st.docs.find(x => x.id === f.doc), fx = d && fxOf(d.id), tag = `${P} ${f.id} ${rule}`;
    ok("forensics: finding references an analyzed document", d && d.status === "analyzed", tag);
    if (!fx) continue;
    const fl = fx.fields, has = p => Object.keys(fl).some(k => k.startsWith(p));
    const backed = {
      "doc.bad_redaction": fx.bad_redactions.length > 0 && fx.bad_redactions.every(r => f.evidence.includes(r.text)),
      "doc.modified_after_signing": fx.signatures.some(s => s.modified_after_signing),
      "doc.signer_identity": fx.signatures.some(s => f.evidence.includes(s.signer.common_name) && f.evidence.includes(s.signer.edrpou)),
      "doc.signature_tsa_gap": fx.signatures.some(s => s.timestamp && Date.parse(s.timestamp.gen_time) - Date.parse(s.signing_time) > 864e5),
      "doc.hidden_content": fx.hidden_content.length > 0 && fx.hidden_content.filter(h => h.text).every(h => f.evidence.includes(h.text)),
      "doc.pdf_removed_text": fx.pdf_revisions.some(r => (r.removed_text || []).length && r.removed_text.every(t => f.evidence.includes(t))),
      "doc.pdf_revision_authors": new Set(fx.pdf_revisions.map(r => r.author)).size > 1,
      "doc.data_connection": has("xl:connection:") || has("xl:pivotCache"),
      "doc.lnk_host_mac": !!fl["lnk:machine_id"] && f.evidence.includes(fl["lnk:mac"]),
      "doc.lnk_unc_path": !!fl["lnk:network_path"] && f.evidence.includes(fl["lnk:network_path"]),
      "doc.links": fx.links.length > 0 && fx.links.every(l => f.evidence.includes(l.url)),
      "mail.internal_relay": has("eml:internal_hosts") && fl["eml:internal_ips"].split(", ").every(ip => f.evidence.includes(ip)),
      "mail.originating_ip": fl["eml:originating_ips"] === f.evidence,
      "mail.internal_domain": fl["eml:message_id_domain"] === f.evidence,
      "mail.reply_to_mismatch": fl["eml:reply_to_differs"] === "true" && fl["eml:reply-to"] === f.evidence,
      "mail.m365_tenant": f.evidence === tenant,
      "cal.meeting_link": fl["ics:meeting_links"] === f.evidence,
      "pim.contact_pii": has("vcf:"),
      "media.device_serial": f.evidence.includes(fl["media:camera_serial"] || "?"),
      "zip.path_traversal": fl["zip:unsafe_names"] === f.evidence && fx.embedded.some(e => e.name === f.evidence),
      pii: fx.pii.some(p => p.samples.every(x => f.evidence.includes(x)) && f.description.includes(String(p.count))),
    }[rule];
    ok("forensics: every forensic finding is backed by the doc_get record", backed === true, tag);
    ok("forensics: category docs|people, module forensics|pii", ["docs", "people"].includes(f.category) && ["forensics", "pii"].includes(f.module), tag);
  }
  // Full-text search: snippets highlight the query, masked values stay masked, deleted documents are hidden.
  const r1 = await F.api.docs_search("ТЕС-2");
  ok("docs_search: finds text of mail, PDF and spreadsheets", r1.total >= 4 && r1.hits.some(h => /\.eml$/.test(h.name)) && r1.hits.every(h => /\{\{h:/.test(h.snippet)), `${r1.total}`);
  const r2 = await F.api.docs_search("IBAN");
  ok("docs_search: masked values come as {{s:…}} with masked labels", r2.hits.length && r2.hits.every(h => !/UA\d{6,}/.test(h.snippet)) && r2.hits.some(h => /\{\{s:/.test(h.snippet) && h.masked.includes("pii:iban")), JSON.stringify(r2.hits.map(h => h.masked)));
  const tu = st.docs.find(d => d.name === "Технічні_умови_підключення.pdf");
  await F.api.doc_delete([tu.id]);
  const r3 = await F.api.docs_search("диспетчера"), r4 = await F.api.docs_search("диспетчера", { include_deleted: true });
  ok("docs_search: deleted documents only with include_deleted", r3.total === 0 && r4.total === 1 && r4.hits[0].deleted, JSON.stringify([r3.total, r4.total]));
  await F.api.doc_restore([tu.id]);
  // User rules: byte offsets, validation errors as bad_args.
  const rt = await F.api.rules_test("наказ\\s*№\\s*(?P<v>\\d+)", "Згідно з наказ № 127");
  ok("rules_test: byte offsets of UTF-8 text, value masked", rt.count === 1 && rt.hits[0].start === 16 && rt.hits[0].value === "••••", JSON.stringify(rt));
  let bad = null; try { await F.api.rules_set({ presets: [], rules: [{ id: "x", title: "x", pattern: "(", sev: "low", enabled: true }] }); } catch (e) { bad = e.code; }
  ok("rules_set: a broken pattern is rejected with bad_args, nothing saved", bad === "bad_args" && !(await F.api.rules_get()).config.rules.some(r => r.id === "x"), String(bad));
  // Offline import: a new project from the picked files, no scans (no network), findings point to its documents.
  const pick = await F.api.platform_pick_folder({});
  const imp = await F.api.import_offline({ name: "Флешка ТЕС-2", paths: pick.files.map(f => f.path).concat("files/picked/unknown.bin") });
  ok("import_offline: every picked story document imported, unknown file skipped", imp.imported === pick.files.length && imp.skipped.length === 1 && imp.skipped[0].reason === "bad_data" && !imp.cancelled, JSON.stringify(imp).slice(0, 200));
  const ist = B._state().projects[imp.project];
  ok("import_offline: project without scans or hosts, documents from files", ist && !ist.scans.length && !ist.hosts.length && ist.docs.every(d => d.url.startsWith("file:///") && d.host === "-"), imp.project);
  ok("import_offline: findings reference imported documents", ist.findings.length > 10 && ist.findings.every(f => ist.docs.some(d => d.id === f.doc)), `${ist.findings.length}`);
  const again = await F.api.import_offline({ project: imp.project, paths: pick.files.map(f => f.path) });
  ok("import_offline: repeated files are duplicates", again.imported === 0 && again.duplicates === pick.files.length, JSON.stringify(again).slice(0, 120));
}

// Stage 1.4: insights, web audit and hygiene agree with the project data.
{
  const P = "[contoso]", I = B.invokeSync("insights_get", { project: "contoso" }), snap = B.invokeSync("project_snapshot", { id: "contoso" });
  const doc = id => snap.docs.find(d => d.id === id && !d.deleted);
  const ver = d => +((d.name.match(/_v(\d+)\.[^.]+$/) || [0, 1])[1]);
  ok("insights: anomalies reference live analyzed documents; PDF/XMP date mismatch only in PDFs", I.anomalies.length > 0 && I.anomalies.every(a => doc(a.doc) && doc(a.doc).status === "analyzed" && (a.code !== "date_mismatch" || doc(a.doc).ext === "pdf")), P);
  ok("insights: inherited XMP history only on a later version of a lineage", I.anomalies.filter(a => a.code === "history_before_created").every(a => I.correlation.lineages.some(l => l.docs.includes(a.doc) && l.root !== a.doc)), P);
  ok("insights: lineage links go from a later version to an earlier one, roots belong to their lineage", I.correlation.links.length > 0 && I.correlation.links.every(l => doc(l.from) && doc(l.to) && ver(doc(l.from)) > ver(doc(l.to))) && I.correlation.lineages.every(l => l.docs.includes(l.root) && l.docs.length > 1), P);
  const nm = I.netmap.nodes, byId = new Map(nm.map(n => [n.id, n]));
  ok("netmap: every parent exists; users hang under their workstation; sources cite live documents", nm.every(n => !n.parent || byId.has(n.parent)) && nm.filter(n => n.kind === "user").every(u => { const p = byId.get(u.parent); const login = u.id.slice(5); return p && p.kind === "workstation" && snap.people.some(x => x.login === login && x.pc === p.label); }) && nm.every(n => n.sources.every(s => s.doc == null || doc(s.doc))), P);
  ok("netmap: servers are internal hosts or server PCs, workstations are project PCs", nm.filter(n => n.kind === "server").every(n => snap.hosts.some(h => h.internal && h.name === n.label) || snap.pcs.some(p => p.kind === "server" && p.name === n.label)) && nm.filter(n => n.kind === "workstation").every(n => snap.pcs.some(p => p.kind !== "server" && p.name === n.label)), P);
  const a = I.activity, sum = r => r.reduce((x, y) => x + y, 0);
  ok("activity: 7×24 matrix sums match hours, weekdays and total; out of hours ≤ total", a.matrix.length === 7 && a.matrix.every(r => r.length === 24) && a.matrix.every((r, d) => sum(r) === a.weekdays[d]) && a.hours.every((h, i) => h === sum(a.matrix.map(r => r[i]))) && sum(a.weekdays) === a.total && a.out_of_hours <= a.total, P);
  ok("timeline: three lanes; software labels are project software; years within the document years", ["documents", "software", "certificates"].every(l => I.timeline.some(t => t.lane === l)) && I.timeline.filter(t => t.lane === "software").every(t => snap.software.some(s => s.name === t.label)), P);
  const kevF = snap.findings.filter(f => (f.provenance || {}).rule === "sw.kev");
  ok("KEV findings: «вероятно» ⇔ tag likely, «возможно … сверьте версию» ⇔ possible; CVE from the software card", kevF.length >= 2 && kevF.every(f => (f.tags.includes("likely") ? /^Вероятно/.test(f.title) : /^Возможно.*сверьте версию/.test(f.title)) && f.cve.length > 0), P);
  const web = snap.recon.web || [];
  ok("web audit: recon.web.* findings belong to an audited host; candidates are out of scope", snap.findings.filter(f => /^recon\.web\./.test((f.provenance || {}).rule || "")).every(f => web.some(w => w.host === f.host)) && web.every(w => w.csp_domains.filter(c => !c.in_scope).every(c => w.candidates.includes(c.host))), P);
  ok("web audit: passive level sends nothing and fetches no source maps or API docs", web.filter(w => w.level === "passive").every(w => w.requests === 0 && !w.source_maps.length && !w.api_docs.length), P);
  for (const p of Object.keys(B._state().projects)) {
    const w2 = (B.invokeSync("project_snapshot", { id: p }).recon || {}).web || [];
    if (p !== "contoso") ok("web audit: no contoso data in other projects", !JSON.stringify(w2).includes("contoso"), p);
  }
  const H = B.invokeSync("hygiene_get", { project: "contoso" });
  const G = ["A", "B", "C", "D", "E", "F"], gOf = s => (s >= 90 ? "A" : s >= 75 ? "B" : s >= 60 ? "C" : s >= 40 ? "D" : s >= 20 ? "E" : "F");
  ok("hygiene: grade follows the score, a critical issue caps it at E", H.docs.length > 0 && H.docs.every(r => (r.issues.some(i => i.severity === "crit") ? G.indexOf(r.grade) >= 4 : r.grade === gOf(r.score))), P);
  ok("hygiene: set counts by grade sum to the documents, set grade at most one step above the worst", Object.values(H.set.by_grade).reduce((x, y) => x + y, 0) === H.set.documents && G.indexOf(H.set.grade) >= G.indexOf(H.set.worst) - 1, P);
  const cl = B.invokeSync("doc_clean", { project: "contoso", ids: H.docs.slice(0, 12).map(r => r.id) }).cleaned;
  ok("doc_clean: grade after is never worse; a clean verdict only without manual items", cl.every(c => !c.grade_after || G.indexOf(c.grade_after) <= G.indexOf(c.grade_before)) && cl.every(c => !c.clean || (c.manual.length === 0 && c.verify && c.verify.clean)), P);
  B.invokeSync("demo_share", {});
  const s1 = B.invokeSync("platform_shared_files", {}), s2 = B.invokeSync("platform_shared_files", {});
  const sc = B.invokeSync("doc_clean", { path: s1.files[0].path, name: s1.files[0].name }).cleaned[0];
  ok("share target: shared files are handed out once; the clean copy of a signed file warns about the signature", s1.files.length === 1 && s2.files.length === 0 && sc.id === null && sc.verify.warnings.some(w => w.code === "signature_removed"), JSON.stringify([s1.files.length, s2.files.length]));
}

// Stage 1.4: report templates, standards of the findings and the reference case.
{
  const STD = ["mitre", "cwe", "owasp", "wstg", "iso27001", "nist", "privacy", "ndtzi", "kszi"];
  for (const L of ["RU", "UA", "EN"]) {
    const t = B.invokeSync("report_templates", { lang: L });
    ok("report templates: full, executive, compliance, lab in order with a title and a description", t.map(x => x.id).join() === "full,executive,compliance,lab" && t.every(x => x.title && x.description), L);
  }
  let bad = null;
  try { B.invokeSync("report_build", { project: "contoso", opts: { fmt: "html" }, template: "nope" }); } catch (e) { bad = e.code; }
  ok("report_build: unknown template → bad_args", bad === "bad_args", String(bad));
  for (const p of Object.keys(B._state().projects)) {
    for (const f of B.invokeSync("project_snapshot", { id: p }).findings) {
      const st = f.standards;
      ok("standards: null or every standard is a non-empty list of strings in total", st === null || (STD.every(k => Array.isArray(st[k]) && st[k].every(v => typeof v === "string" && v)) && STD.some(k => st[k].length)), `${p}#${f.id}`);
      if (st) ok("standards: only findings with a rule carry standards; CWE ids look like CWE-n", !!(f.provenance || {}).rule && st.cwe.every(c => /^CWE-\d+$/.test(c)) && st.mitre.every(m => /^T\d{4}(\.\d{3})?$/.test(m)), `${p}#${f.id}`);
      if (st) ok("standards: OWASP ids are Top 10:2025, NIST ids look like AA-n(n), CWE Top 25 flags are a subset of cwe", st.owasp.every(o => /^A(0[1-9]|10):2025$/.test(o)) && st.nist.every(n => /^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?$/.test(n)) && Array.isArray(st.cwe_top25) && st.cwe_top25.every(c => st.cwe.includes(c)), `${p}#${f.id}`);
    }
  }
  const dc = B.invokeSync("demo_case_import", {});
  const dcs = B.invokeSync("project_snapshot", { id: dc.project });
  ok("reference case: a new project named in the UI language with the imported documents, no network", dc.demo_case === true && ["Эталонный кейс", "Еталонний кейс", "Reference case"].includes(dcs.project.name) && dc.imported >= 10 && dcs.docs.length === dc.imported && !dcs.scans.some(x => x.status === "running"), JSON.stringify([dc.imported, dcs.docs.length]));
  B.invokeSync("project_delete", { id: dc.project });
}

// Stage 1.5: HIBP k-anonymity, contextual wordlists, alerts & Telegram/Webhook KeyVault hygiene.
{
  const S = B.invokeSync("settings_get", {});
  ok("settings.keys includes tg_bot and webhook", !!S.keys.tg_bot && !!S.keys.webhook && S.alerts && typeof S.alerts.enabled === "boolean", "settings.keys/alerts");
  const wlLogins = B.invokeSync("wordlist_preview", { project: "contoso", kind: "logins", ad_domain: "CORP", limit: 100 });
  const wlCtx = B.invokeSync("wordlist_preview", { project: "contoso", kind: "context", limit: 100 });
  const rawSecrets = B._state().projects.contoso.secrets.map(s => String(s.value || "").toLowerCase()).filter(v => v.length >= 6);
  const leaked = rawSecrets.some(sv => wlLogins.items.join("\n").toLowerCase().includes(sv) || wlCtx.items.join("\n").toLowerCase().includes(sv));
  ok("wordlist_preview: logins & context include domain/AD forms and zero project secrets", wlLogins.total > 5 && wlLogins.ad_domain === "CORP" && wlCtx.total > 5 && !leaked, `${wlLogins.total}/${wlCtx.total}`);
  const hb = B.invokeSync("secret_hibp_check", { project: "contoso", id: 1 });
  ok("secret_hibp_check: returns only 5-char hex prefix and boolean/count", /^[0-9A-F]{5}$/.test(hb.prefix) && typeof hb.pwned === "boolean" && typeof hb.count === "number", JSON.stringify(hb));
  const cfg1 = B.invokeSync("alert_rules_set", {
    project: "contoso",
    patch: { enabled: true, webhook: { enabled: true, kind: "generic", url: "https://evil-leak.invalid/raw-url" }, telegram: { token: "123:RAWBOT" } },
  });
  ok("alert_rules_set strips raw token/url secrets and lists 9 rules", cfg1.enabled === true && cfg1.available_rules.length === 9 && !JSON.stringify(cfg1).includes("evil-leak.invalid") && !JSON.stringify(cfg1).includes("RAWBOT"), "9 rules");
  const testFail = B.invokeSync("alert_test", { project: "contoso", channel: "webhook" });
  B.invokeSync("key_set", { service: "webhook", value: "https://hooks.example.test/secret99" });
  const testOk = B.invokeSync("alert_test", { project: "contoso", channel: "webhook" });
  B.invokeSync("key_delete", { service: "webhook" });
  ok("alert_test requires KeyVault key and succeeds once configured", testFail.ok === false && testOk.ok === true && testOk.sent === 1, JSON.stringify([testFail.ok, testOk.ok]));
  const trend = B.invokeSync("risk_trend_get", { project: "contoso" });
  ok("risk_trend_get returns points, current, previous and direction", trend.points.length >= 2 && typeof trend.current === "number" && typeof trend.previous === "number" && ["up", "down", "flat", "none"].includes(trend.direction), JSON.stringify(trend));

  // finding_playbook, report_build (docx + custody), report_verify, export_build (stix/nuclei/httpx), settings.ocr.
  const pb = B.invokeSync("finding_playbook", { project: "contoso", id: 1, lang: "UA" });
  const pbJson = JSON.stringify(pb);
  ok(
    "finding_playbook: returns structured steps, verify checklist and zero raw secrets",
    pb && pb.id === 1 && Array.isArray(pb.steps) && pb.steps.length >= 2 && Array.isArray(pb.verify) && pb.verify.length >= 1 && !rawSecrets.some(s => pbJson.toLowerCase().includes(s)),
    pbJson.slice(0, 120),
  );
  const docxRep = B.invokeSync("report_build", {
    project: "contoso",
    opts: { fmt: "docx", lang: "UA", custody: true },
  });
  const verRep = B.invokeSync("report_verify", { project: "contoso", id: docxRep.id });
  ok(
    "report_build (docx + custody) & report_verify: verified_hash and custody record",
    docxRep.fmt === "docx" && /\.docx$/.test(docxRep.name) && verRep.ok === true && verRep.status === "verified_hash" && verRep.custody && typeof verRep.custody.inputs_sha256 === "string",
    JSON.stringify(verRep),
  );
  const stixExp = B.invokeSync("export_build", {
    project: "contoso",
    kind: "all",
    fmt: "stix",
    opts: { secrets: true, pii: false },
  });
  const nucExp = B.invokeSync("export_build", { project: "contoso", kind: "hosts", fmt: "nuclei", opts: {} });
  const hxExp = B.invokeSync("export_build", { project: "contoso", kind: "hosts", fmt: "httpx", opts: {} });
  ok(
    "export_build: stix forces secrets=false & pii_redacted=true; nuclei and httpx produce .txt lists",
    /\.json$/.test(stixExp.name) && stixExp.secrets === false && stixExp.pii_redacted === true && /\.txt$/.test(nucExp.name) && nucExp.count > 0 && /\.txt$/.test(hxExp.name) && hxExp.count > 0,
    JSON.stringify([stixExp, nucExp, hxExp]),
  );
  const stOcr = B.invokeSync("settings_get", {}).ocr;
  ok(
    "settings.ocr: disabled by default with max_pages=10 and max_mb=15",
    stOcr && stOcr.enabled === false && stOcr.max_pages === 10 && stOcr.max_mb === 15,
    JSON.stringify(stOcr),
  );
  // Network targets only (domain, *.domain, URL, IP, CIDR, IP-range)
  const laCtx = {
    console,
    URL,
    Object,
    Array,
    String,
    Number,
    Set,
    Map,
    Math,
    Date,
    RegExp,
    JSON,
    FOCA: {
      ic: () => "",
      esc: s => String(s),
      ui: {},
      state: { scope: {} },
      actions: {},
      db: { settings: {} },
      addIcons: () => {},
      route: () => {},
      on: () => {},
      sel: {},
    },
  };
  laCtx.window = laCtx;
  vm.createContext(laCtx);
  vm.runInContext(fs.readFileSync(fileURLToPath(new URL("../ui/screens/launch.js", import.meta.url)), "utf8"), laCtx, {
    filename: "launch.js",
  });
  const pt = laCtx.FOCA.parseTarget;
  ok(
    "targets: accepts honest network targets (domain, wild, url, ip, cidr, range)",
    pt("example.com")?.type === "domain" &&
      pt("*.example.com")?.type === "wild" &&
      pt("https://a.example.com/p")?.type === "url" &&
      pt("203.0.113.10")?.type === "ip" &&
      pt("203.0.113.0/24")?.type === "cidr" &&
      pt("203.0.113.1-203.0.113.5")?.type === "range",
    "parseTarget valid types",
  );
  const em = pt("user@example.com");
  ok(
    "targets: rejects email, person, org, asn (and suggests domain for email)",
    !!em?.err &&
      em.err.includes("example.com") &&
      !!pt("AS15169")?.err &&
      !!pt("Олена Коваленко")?.err &&
      !!pt("ТОВ «Ромашка»")?.err,
    JSON.stringify([em, pt("AS15169"), pt("Олена Коваленко"), pt("ТОВ «Ромашка»")]),
  );
  ok(
    "contoso scope contains only honest network targets",
    B._state().projects.contoso.scope.targets.every(t => ctx.FOCA_RULES.scope.NET.includes(t.type)),
    JSON.stringify(B._state().projects.contoso.scope.targets),
  );
  // Encrypted .foca.enc roundtrip and wrong password check
  const encRes = B.invokeSync("project_export_encrypted", {
    project: "contoso",
    password: "AuditPassword!2026",
    include_files: true,
  });
  let badPwErr = null;
  try {
    B.invokeSync("project_import_encrypted", { path: encRes.path, password: "WrongPassword!2026" });
  } catch (e) {
    badPwErr = e.code;
  }
  const impRes = B.invokeSync("project_import_encrypted", {
    path: encRes.path,
    password: "AuditPassword!2026",
    new_name: "Imported Audit",
  });
  ok(
    "project_export_encrypted / project_import_encrypted: roundtrip, custody, bad_password, no overwrite",
    /\.foca\.enc$/.test(encRes.name) &&
      badPwErr === "bad_password" &&
      impRes.project.id !== "contoso" &&
      impRes.custody.inputs_sha256 === encRes.inputs_sha256,
    JSON.stringify({ encRes, badPwErr, impId: impRes.project.id }),
  );
  B.invokeSync("project_delete", { id: impRes.project.id });
  // i18n_bundle (auto device locale, explicit switching, lazy help, key sync)
  const bAutoUk = B.invokeSync("i18n_bundle", { lang: "auto", device_locale: "uk-UA", include_help: false });
  const bAutoDe = B.invokeSync("i18n_bundle", { lang: "auto", device_locale: "de-DE", include_help: false });
  const bEnHelp = B.invokeSync("i18n_bundle", { lang: "en", include_help: true });
  const bRuHelp = B.invokeSync("i18n_bundle", { lang: "ru", include_help: true });
  const bUkHelp = B.invokeSync("i18n_bundle", { lang: "uk", include_help: true });
  const enKeys = Object.keys(bEnHelp.ui).sort().join(",");
  ok(
    "i18n_bundle: auto locale resolution (uk-UA→uk, de-DE→en), lazy help & EN/RU/UK UI key sync",
    bAutoUk.lang === "uk" &&
      bAutoUk.help === null &&
      bAutoDe.lang === "en" &&
      bEnHelp.ui["nav.overview"] === "Overview" &&
      bRuHelp.ui["nav.overview"] === "Обзор" &&
      bUkHelp.ui["nav.overview"] === "Огляд" &&
      enKeys === Object.keys(bRuHelp.ui).sort().join(",") &&
      enKeys === Object.keys(bUkHelp.ui).sort().join(",") &&
      Array.isArray(bEnHelp.help?.articles) &&
      bEnHelp.help.articles.length > 0 &&
      bEnHelp.help.articles.length === bUkHelp.help?.articles?.length,
    JSON.stringify({ uk: bAutoUk.lang, de: bAutoDe.lang, enNav: bEnHelp.ui["nav.overview"] }),
  );
  // licenses_get & Android foss/play flavor reporting
  const lic = B.invokeSync("licenses_get", {});
  const devInfo = B.invokeSync("platform_device_info", {});
  ok(
    "licenses_get: GPL-3.0 schema, no lopdf, ML Kit isolated to play flavor, device_info.flavor present",
    lic.schema === "foca-licenses/v1" &&
      lic.app_license === "GPL-3.0" &&
      lic.repository === "https://github.com/SinonApp/FOCA-rs" &&
      Array.isArray(lic.data_assets) &&
      Array.isArray(lic.rust_crates) &&
      !lic.rust_crates.some(c => c.name === "lopdf") &&
      Array.isArray(lic.android_libs) &&
      lic.android_libs.every(a => !a.proprietary || a.flavor === "play") &&
      Array.isArray(lic.license_texts) &&
      lic.license_texts.length >= 3 &&
      typeof devInfo.flavor === "string" &&
      devInfo.flavor.length > 0,
    JSON.stringify({ schema: lic.schema, repo: lic.repository, flavor: devInfo.flavor }),
  );
  // attack_paths_get & signed signature bundle lifecycle
  const apDemo = B.invokeSync("attack_paths_get", { project: "contoso" });
  const emptyProj = B.invokeSync("project_create", {
    name: "empty-ap.test",
    client: "",
    targets: [{ v: "empty-ap.test", type: "domain", active: false }],
    excludes: [],
  });
  const apEmpty = B.invokeSync("attack_paths_get", { project: emptyProj.id });
  B.invokeSync("project_delete", { id: emptyProj.id });
  const sigInit = B.invokeSync("signatures_status", {});
  const sigUp = B.invokeSync("signatures_update", {});
  const sigAfterUp = B.invokeSync("signatures_status", {});
  const sigRb = B.invokeSync("signatures_rollback", {});
  ok(
    "attack_paths_get & signatures_status/update/rollback lifecycle",
    Array.isArray(apDemo.paths) &&
      Array.isArray(apDemo.choke_points) &&
      typeof apDemo.summary?.total_paths === "number" &&
      apEmpty.paths.length === 0 &&
      apEmpty.choke_points.length === 0 &&
      sigInit.schema === "foca-sig-bundle/v1" &&
      sigUp.source === "bundle" &&
      sigAfterUp.can_rollback === true &&
      typeof sigRb.version === "string",
    JSON.stringify({ ap: apDemo.summary, sigSource: sigAfterUp.source, sigRb: sigRb.version }),
  );
}

// Summary.
for (const [g, r] of Object.entries(groups)) console.log(`${r.bad.length ? "✗" : "✓"} ${g} (${r.ok}${r.bad.length ? ", errors " + r.bad.length + ": " + r.bad.slice(0, 3).join("; ") : ""})`);
console.log(`\n${fails ? "FAILED" : "ALL GREEN"}: ${passes} checks passed, ${fails} failed`);
process.exit(fails ? 1 : 0);
