// Finding texts catalog for the demo backend, the same object the core serves as `i18n_bundle().findings`
// (locales/<lang>/findings.json + the `sources` table of report.json). Injected as window.FOCA_DEMO_FINDINGS.
import fs from "fs";
import path from "path";

export function demoFindings(root) {
  const out = {};
  for (const l of ["en", "uk"]) {
    const f = JSON.parse(fs.readFileSync(path.join(root, "locales", l, "findings.json"), "utf8"));
    const r = JSON.parse(fs.readFileSync(path.join(root, "locales", l, "report.json"), "utf8"));
    out[l] = {
      catalog: f.catalog,
      terms: f.terms,
      roles: f.roles,
      tech_cats: f.tech_cats,
      host_sources: f.host_sources,
      sources: r.sources,
    };
  }
  return out;
}
