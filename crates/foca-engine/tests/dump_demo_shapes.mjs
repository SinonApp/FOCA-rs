// Response shapes of the demo backend (the contract reference) → tests/fixtures/demo_shapes.json.
// Run: node crates/foca-engine/tests/dump_demo_shapes.mjs
// A shape is keys and types, no values. For arrays of objects the required keys are those present
// in EVERY element; for dictionaries keyed by data (settings.keys, leaks, snapshot.hosts…) it is the value shape.
import fs from "fs";
import { fileURLToPath } from "url";
import vm from "vm";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = fileURLToPath(new URL("../../../ui/js/", import.meta.url));
const ctx = { console, setTimeout, clearTimeout, Promise, JSON, Math, Date, Map, Set, Object, Array, String, Number, Proxy, encodeURIComponent, decodeURIComponent };
ctx.window = ctx; ctx.globalThis = ctx; ctx.FOCA = { state: {}, actions: {} };
vm.createContext(ctx);
for (const f of ["demo-backend.js", "api.js", "sel.js"]) vm.runInContext(fs.readFileSync(root + f, "utf8"), ctx, { filename: f });
const B = ctx.FOCA_DEMO_BACKEND;

const MAPS = ["settings.keys", "settings.plugins", "settings.monitor", "settings.report.picked", "settings.report.draft", "settings.ui.std_ok",
  "leaks", "scans[].snapshot.hosts", "scans[].snapshot.findings", "scan.snapshot.hosts", "scan.snapshot.findings",
  "scans[].snapshot.tech", "scan.snapshot.tech", "keys", "plugins", "monitor", "ct[].orgs", "forensics.fields",
  "org.people[].roles", "activity.tz_counts", "set.by_grade", "controls",
  "findings.roles", "findings.tech_cats", "findings.host_sources", "findings.sources"];
const isMap = path => MAPS.some(m => path === m || path.endsWith("." + m));

function typeOf(v) { return v === null || v === undefined ? "null" : Array.isArray(v) ? "array" : typeof v === "object" ? "object" : typeof v === "boolean" ? "bool" : typeof v; }

function shape(v, path = "") {
  const t = typeOf(v);
  if (t === "array") {
    let items = null;
    for (const x of v) items = items ? merge(items, shape(x, path + "[]")) : shape(x, path + "[]");
    return { t: ["array"], items };
  }
  if (t === "object") {
    if (isMap(path)) {
      let values = null;
      for (const x of Object.values(v)) values = values ? merge(values, shape(x, path + ".*")) : shape(x, path + ".*");
      return { t: ["map"], values };
    }
    const keys = {};
    for (const [k, x] of Object.entries(v)) if (x !== undefined) keys[k] = shape(x, path ? path + "." + k : k);
    return { t: ["object"], keys };
  }
  return { t: [t] };
}

function merge(a, b) {
  const t = [...new Set([...a.t, ...b.t])].sort();
  const out = { t };
  if (a.keys && b.keys) { out.keys = {}; for (const k of Object.keys(a.keys)) if (k in b.keys) out.keys[k] = merge(a.keys[k], b.keys[k]); }
  else if (a.keys || b.keys) out.keys = a.keys || b.keys;
  if ("items" in a || "items" in b) out.items = a.items && b.items ? merge(a.items, b.items) : (a.items || b.items || null);
  if ("values" in a || "values" in b) out.values = a.values && b.values ? merge(a.values, b.values) : (a.values || b.values || null);
  return out;
}

const call = (cmd, args = {}) => B.invokeSync(cmd, args);
const out = { commands: {}, events: {} };
const put = (name, v) => { out.commands[name] = out.commands[name] ? merge(out.commands[name], shape(v)) : shape(v); };

put("project_list", call("project_list"));
put("project_snapshot", call("project_snapshot", { id: "contoso" }));
put("project_snapshot", call("project_snapshot", { id: "logistics" }));
put("project_open", call("project_open", { id: "contoso" }));
put("scope_get", call("scope_get", { id: "contoso" }));
const np = call("project_create", { name: "shape.ua", client: "К", targets: [{ v: "shape.ua", type: "domain", active: false }], excludes: [] });
put("project_create", np);
put("project_update", call("project_update", { id: np.id, patch: { notes: "n" } }));
const dup = call("project_duplicate", { id: np.id });
put("project_duplicate", dup);
put("project_delete", call("project_delete", { id: dup.id }));
const encExp = call("project_export_encrypted", { project: "contoso", password: "DemoPassword!2026", include_files: true });
put("project_export_encrypted", encExp);
const encImp = call("project_import_encrypted", { path: encExp.path, password: "DemoPassword!2026", new_name: "Imported Demo" });
put("project_import_encrypted", encImp);
call("project_delete", { id: encImp.project.id });
put("scope_set", call("scope_set", { id: "contoso", scope: { contact: "x" } }));
put("oos_list", call("oos_list", { project: "contoso" }));
put("infra_get", call("infra_get", { project: "contoso" }));
// Analytics and link chains.
put("insights_get", call("insights_get", { project: "contoso" }));
put("insights_get", call("insights_get", { project: "contoso", layers: ["people", "docs"], min_group: 2 }));
put("chain_get", call("chain_get", { project: "contoso", from_id: 3 }));
put("attack_paths_get", call("attack_paths_get", { project: "contoso" }));
const oos = call("oos_list", { project: "contoso" });
const cand = oos.find(o => !o.blocked && o.decision === "new");
put("oos_decide", call("oos_decide", { project: "contoso", id: cand.id, decision: "ignored" }));
call("oos_decide", { project: "contoso", id: cand.id, decision: "new" });
put("oos_add_to_scope", call("oos_add_to_scope", { project: "contoso", id: cand.id }));
put("scope_add_hosts", call("scope_add_hosts", { project: "contoso", hosts: ["intranet.contoso-partner.example", "portal.contoso.example"], dry_run: true }));
put("finding_set_status", call("finding_set_status", { project: "contoso", id: 5, status: "confirmed" }));
put("finding_update", call("finding_update", { project: "contoso", id: 7, patch: { notes: [{ text: "t", who: "Вы", time: "20.11" }] } }));
put("finding_photo_add", call("finding_photo_add", { project: "contoso", id: 7, name: "a.jpg" }));
put("cve_list", call("cve_list", { product: "microsoft:office", version: "15.0.4420" }));
put("finding_playbook", call("finding_playbook", { project: "contoso", id: 7, lang: "uk" }));
put("doc_delete", call("doc_delete", { project: "contoso", ids: [20] }));
put("doc_restore", call("doc_restore", { project: "contoso", ids: [20] }));
put("doc_clean", call("doc_clean", { project: "contoso", ids: [1, 3] }));
put("doc_clean_file", call("doc_clean", { path: "/tmp/shared/a.pdf", name: "a.pdf" }));
put("hygiene_get", call("hygiene_get", { project: "contoso" }));
put("hygiene_get_file", call("hygiene_get", { path: "/tmp/shared/a.pdf", name: "a.pdf" }));
put("secret_reveal", call("secret_reveal", { project: "contoso", id: 1 }));
put("secret_reveal_ref", call("secret_reveal", { project: "contoso", id: "f4:0" }));
put("secret_hibp_check", call("secret_hibp_check", { project: "contoso", id: 1 }));
put("settings_get", call("settings_get"));
put("settings_set", call("settings_set", { patch: { net: { rps: 5 } } }));
put("key_set", call("key_set", { service: "brave", value: "BSAqxxxxxxab12" }));
put("key_delete", call("key_delete", { service: "censys" }));
put("net_check", call("net_check"));
put("mobile_usage", call("mobile_usage"));
put("key_check", call("key_check", { service: "searx", value: "https://searx.example.org" }));
put("dorks_pending", call("dorks_pending", { project: "contoso" }));
put("dorks_retry", call("dorks_retry", { project: "contoso" }));
// Offline import, full-text search, user rules, document forensics.
put("import_offline", call("import_offline", { project: "contoso", paths: [] }));
put("demo_case_import", call("demo_case_import", {}));
put("import_cancel", call("import_cancel"));
{
  const d0 = call("project_snapshot", { id: "contoso" }).docs.find(d => !d.deleted);
  put("docs_search", call("docs_search", { project: "contoso", q: d0.name.slice(0, 4) }));
  put("doc_get", call("doc_get", { project: "contoso", id: d0.id }));
}
put("rules_get", call("rules_get", { project: "contoso" }));
put("rules_set", call("rules_set", { project: "contoso", config: { presets: ["credentials"], rules: [{ id: "r1", title: "Проект", pattern: "проект\\s+\\w+", sev: "low", enabled: true, case_insensitive: true, mask: false }] } }));
put("rules_test", call("rules_test", { pattern: "\\d{4}", text: "код 1234 і 5678" }));
put("report_list", call("report_list", { project: "contoso" }));
const rep = call("report_build", { project: "contoso", opts: { tpl: "Полный отчёт пентеста", tpl_id: "full", fmt: "html", lang: "RU", min_sev: "low", confirmed: false, sections: { summary: true, findings: true } } });
put("report_build", rep);
const repCust = call("report_build", { project: "contoso", custody: true, opts: { tpl_id: "full", fmt: "html", lang: "UK" } });
put("report_build", repCust);
put("report_templates", call("report_templates", { lang: "UA" }));
put("report_logo_set", call("report_logo_set", { data: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAECAIAAAA8r+mnAAAAJUlEQVR42mNgCDghF3DCJuBEVMCJioAT0wJObAk4cSngBAP1JAAgOzAh+r1X4QAAAABJRU5ErkJggg==", name: "logo.png" }));
put("report_logo_get", call("report_logo_get", {}));
put("report_logo_clear", call("report_logo_clear", {}));
put("report_build", call("report_build", { project: "contoso", template: "lab", opts: { fmt: "html", lang: "UA" } }));
put("report_verify", call("report_verify", { project: "contoso", id: rep.id }));
put("report_verify", call("report_verify", { project: "contoso", id: repCust.id }));
put("report_delete", call("report_delete", { project: "contoso", id: rep.id }));
put("export_build", call("export_build", { project: "contoso", kind: "users", fmt: "dict", opts: { dict: "users" } }));
put("export_build", call("export_build", { project: "contoso", kind: "all", fmt: "stix", opts: { pretty: true } }));
put("export_build", call("export_build", { project: "contoso", kind: "all", fmt: "nuclei", opts: {} }));
put("export_build", call("export_build", { project: "contoso", kind: "all", fmt: "httpx", opts: {} }));
put("wordlist_preview", call("wordlist_preview", { project: "contoso", kind: "logins", ad_domain: "CORP", limit: 50 }));
put("wordlist_preview", call("wordlist_preview", { project: "contoso", kind: "context", limit: 50 }));
put("alert_rules_get", call("alert_rules_get", { project: "contoso" }));
put("alert_rules_set", call("alert_rules_set", { project: "contoso", patch: { enabled: true, webhook: { enabled: true, kind: "generic" } } }));
put("alert_test", call("alert_test", { project: "contoso", channel: "webhook" }));
call("key_set", { service: "webhook", value: "https://hooks.example.test/wh" });
put("alert_test", call("alert_test", { project: "contoso", channel: "webhook" }));
call("key_delete", { service: "webhook" });
put("risk_trend_get", call("risk_trend_get", { project: "contoso" }));
put("risk_trend_get", call("risk_trend_get", { project: "agro" }));
// Signed signature bundles
put("signatures_status", call("signatures_status", {}));
const sigUpd = call("signatures_update", {});
put("signatures_update", sigUpd);
put("signatures_status", call("signatures_status", {}));
put("signatures_rollback", call("signatures_rollback", {}));
// In-app update (no network: the demo check answers up_to_date)
put("update_status", call("update_status", { flavor: "foss" }));
put("update_check", call("update_check", { flavor: "foss" }));
put("update_status", call("update_status", { flavor: "foss" }));
put("update_cancel", call("update_cancel", {}));
// Sandboxed plugins catalog & execution
put("plugins_list", call("plugins_list", {}));
put("plugin_install", call("plugin_install", { manifest: { id: "demo-check", name: "Demo Check", version: "1.0.0", author: "QA", kind: "analyzer", runtime: "declarative", permissions: ["meta:read"], declarative: { extract_kind: "meta_pattern", pattern: "TEST-[0-9]+" } } }));
put("plugin_toggle", call("plugin_toggle", { id: "demo-check", enabled: false }));
put("plugin_run_test", call("plugin_run_test", { id: "ua-gov-edrpou-enricher", target: "example.ua", passive: true, sample_body: "EDRPOU 12345678" }));
put("plugin_run_test", call("plugin_run_test", { id: "robots-sitemap-parser", target: "example.ua", passive: true }));
put("plugin_remove", call("plugin_remove", { id: "demo-check" }));
put("i18n_bundle", call("i18n_bundle", { lang: "auto", device_locale: "uk-UA", include_help: false }));
put("i18n_bundle", call("i18n_bundle", { lang: "en", include_help: true }));
put("licenses_get", call("licenses_get", {}));
put("ai_models_list", call("ai_models_list", { provider: "openai" }));
const ap = call("ai_preview", { project: "contoso", opts: {} });
put("ai_preview", ap);
B._aiDelay(0);
const sm = call("ai_summarize", { project: "contoso", preview_id: ap.id, opts: {} });
put("ai_summarize", sm);
put("ai_summaries_list", call("ai_summaries_list", { project: "contoso" }));
put("ai_summary_use", call("ai_summary_use", { project: "contoso", summary: sm.id }));
put("ai_cancel", call("ai_cancel", { project: "contoso" }));
put("ai_summary_delete", call("ai_summary_delete", { project: "contoso", summary: sm.id }));
// scan: responses and events
put("scan_status_idle", call("scan_status"));
const evs = [];
const off = B.listen(e => evs.push(JSON.parse(JSON.stringify(e))));
put("scan_start", call("scan_start", { project: "agro", profile: "passive" }));
B._ff(12);
put("scan_status", call("scan_status"));
put("scan_pause", call("scan_pause"));
put("scan_resume", call("scan_resume"));
put("scan_stop", call("scan_stop", { reason: "user" }));
const stp = call("project_snapshot", { id: "agro" }).scans.slice(-1)[0];
put("scan_start", call("scan_start", { project: "agro", profile: "passive", resume_from: stp.id }));
B._ff(80);
off();
// Re-analysis of stored documents: status, a synchronous run (wait), cancel without a job.
B._reextractAge("contoso", [1, 2, 3, 5]);
put("reextract_status", call("reextract_status", { project: "contoso" }));
put("project_reextract", call("project_reextract", { project: "contoso", mode: "stored_and_missing", ids: [1, 2, 3, 5], wait: true }));
put("reextract_status", call("reextract_status", { project: "contoso" }));
put("reextract_cancel", call("reextract_cancel", { project: "contoso" }));
put("scan_control", call("scan_control", { kind: "stage", id: "network", action: "pause" }));
for (const e of evs) out.events[e.type] = out.events[e.type] ? merge(out.events[e.type], shape(e)) : shape(e);
// Quick tools without a project and the scan queue
put("tool_file", call("tool_file", { path: "/demo/cache/contract.docx" }));
put("tool_secret", call("tool_secret", { value: "Qwerty2024!", hibp_opt_in: true }));
put("tool_secret", call("tool_secret", { value: "Qwerty2024!", hibp_opt_in: false }));
put("tool_mail_domain", call("tool_mail_domain", { domain: "weak.test" }));
put("tool_host", call("tool_host", { url: "http://127.0.0.1/" }));
put("tool_log", call("tool_log"));
put("tool_log_clear", call("tool_log_clear"));
put("queue_pause", call("queue_pause"));
const qa = call("queue_add", { projects: ["agro", "logistics"], profile: "passive" });
put("queue_add", qa);
put("queue_list", call("queue_list"));
put("queue_remove", call("queue_remove", { id: qa.items[0].id }));
put("queue_clear", call("queue_clear", {}));
put("queue_resume", call("queue_resume"));
// Clearing the request log: a count, then rows older than 30 days
put("request_log_clear", call("request_log_clear", { project: "agro", dry_run: true }));
put("request_log_clear", call("request_log_clear", { project: "agro", days: 30 }));
// Deleting one scan: what it would remove, then the deletion itself
put("scan_delete", call("scan_delete", { project: "agro", scan_id: stp.id, dry_run: true }));
put("scan_delete", call("scan_delete", { project: "agro", scan_id: stp.id }));
put("pin_set", call("pin_set", { pin: "2580" }));
put("pin_check", call("pin_check", { pin: "0000" }));
put("wipe_all", call("wipe_all", { confirm: "WIPE" }));

fs.mkdirSync(here + "fixtures", { recursive: true });
fs.writeFileSync(here + "fixtures/demo_shapes.json", JSON.stringify(out, null, 1) + "\n");
console.log(`demo_shapes.json: ${Object.keys(out.commands).length} команд, ${Object.keys(out.events).length} типов событий`);
