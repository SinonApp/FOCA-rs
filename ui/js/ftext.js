/*
 * Finding texts in the UI language. The core writes finding titles, descriptions, recommendations, evidence,
 * finding sources and host/person roles in Russian; the translations are the report catalog
 * (locales/<lang>/findings.json + the `sources` table of report.json), delivered with the UI dictionary by
 * `i18n_bundle` as `findings`. The matcher is a port of foca-report `ftext.rs`: a catalog entry applies to its
 * rules (`provenance.rule`), its pattern is the Russian text with `{}` (any fragment), `{n}` (number) and `{w}`
 * (one word); the translation inserts `{0}`, translates `{0!}` again and inflects `{0:one|few|many}`.
 * Text without a matching entry (user edits, data) is returned unchanged.
 * Test vectors shared with the Rust side: crates/foca-report/tests/ftext_vectors.json (qa/check-ftext.mjs).
 */
(function (root) {
  const F = (root.FOCA = root.FOCA || {});
  let lang = "ru";
  let data = null;
  let compiled = null;
  const cache = new Map();

  const tokens = pat => {
    const out = [];
    let rest = pat;
    while (rest) {
      let best = -1,
        tok = "";
      for (const p of ["{}", "{n}", "{w}"]) {
        const i = rest.indexOf(p);
        if (i >= 0 && (best < 0 || i < best)) {
          best = i;
          tok = p;
        }
      }
      if (best < 0) {
        out.push({ lit: rest });
        break;
      }
      if (best > 0) out.push({ lit: rest.slice(0, best) });
      out.push({ ph: tok === "{}" ? "any" : tok === "{n}" ? "num" : "word" });
      rest = rest.slice(best + tok.length);
    }
    return out;
  };

  const LETTER = /\p{L}/u;
  const DIGIT = /[0-9]/;

  // Returns the captures (`{}` and `{n}`) or null; failed (token, offset) states are memoized.
  const capture = (toks, text) => {
    const failed = new Set();
    const caps = [];
    const go = (ti, pos) => {
      if (ti === toks.length) return pos === text.length;
      const key = ti * (text.length + 1) + pos;
      if (failed.has(key)) return false;
      const t = toks[ti];
      let ok = false;
      if (t.lit !== undefined) {
        ok = text.startsWith(t.lit, pos) && go(ti + 1, pos + t.lit.length);
      } else if (t.ph === "num" || t.ph === "word") {
        const re = t.ph === "num" ? DIGIT : LETTER;
        let end = pos;
        while (end < text.length) {
          const cp = text.codePointAt(end);
          const ch = String.fromCodePoint(cp);
          if (!re.test(ch)) break;
          end += ch.length;
        }
        if (end > pos) {
          const n = caps.length;
          if (t.ph === "num") caps.push(text.slice(pos, end));
          ok = go(ti + 1, end);
          if (!ok) caps.length = n;
        }
      } else {
        // A data fragment never spans lines; it is empty only at the end of a line.
        let line = text.indexOf("\n", pos);
        if (line < 0) line = text.length;
        for (let e = line === pos ? pos : pos + 1; e <= line; e++) {
          // Keep surrogate pairs together.
          const c = text.charCodeAt(e - 1);
          if (e < line && c >= 0xd800 && c <= 0xdbff) continue;
          const n = caps.length;
          caps.push(text.slice(pos, e));
          if (go(ti + 1, e)) {
            ok = true;
            break;
          }
          caps.length = n;
        }
      }
      if (!ok) failed.add(key);
      return ok;
    };
    return go(0, 0) ? caps : null;
  };

  const pluralForm = (n, forms) => {
    const pick = i => forms[i] ?? forms[forms.length - 1] ?? "";
    if (lang === "en") return pick(n === 1 ? 0 : 2);
    const a = n % 10,
      b = n % 100;
    if (b >= 11 && b <= 14) return pick(2);
    if (a === 1) return pick(0);
    if (a >= 2 && a <= 4) return pick(1);
    return pick(2);
  };

  const ruleMatches = (spec, rule) =>
    spec.split(",").some(s => {
      s = s.trim();
      return s === "*" || s === rule || (s.endsWith("*") && rule.startsWith(s.slice(0, -1)));
    });

  const techCategory = c => (data && data.tech_cats && data.tech_cats[c]) || c;

  const render = (tpl, caps, rule, depth) =>
    tpl.replace(/\{([^{}]*)\}/g, (m0, spec) => {
      const k = spec.search(/[:!]/);
      const idx = k < 0 ? spec : spec.slice(0, k);
      const mode = k < 0 ? "" : spec.slice(k);
      if (!/^\d+$/.test(idx) || caps[+idx] === undefined) return m0;
      const v = caps[+idx];
      if (!mode) return v;
      if (mode === "!") return trWhole(v, rule, depth + 1) ?? techCategory(v);
      if (mode[0] === ":") return `${v} ${pluralForm(parseInt(v, 10) || 0, mode.slice(1).split("|"))}`;
      return m0;
    });

  function trWhole(text, rule, depth) {
    if (depth > 2 || !compiled) return null;
    for (const e of compiled) {
      // A finding without a rule (records of old cores) may match any template.
      if (rule && !ruleMatches(e.rules, rule)) continue;
      const caps = capture(e.toks, text);
      if (caps) return render(e.text, caps, rule, depth);
    }
    return null;
  }

  /**
   * Sentence-by-sentence fallback for a line no template covers whole (the core appends notes
   * such as the out-of-scope caveat): longest translatable run first, unknown sentences stay.
   * Mirrors `tr_sentences` in foca-report src/ftext.rs; null if nothing matched.
   */
  function trSentences(line, rule) {
    const cuts = [];
    for (let i = 0; i < line.length; i++)
      if (".!?".includes(line[i]) && (i + 1 === line.length || line[i + 1] === " ")) cuts.push(i + 1);
    cuts.push(line.length);
    if (cuts.length < 2 || cuts.length > 40) return null;
    const out = [];
    let hit = false;
    let pos = 0;
    while (pos < line.length) {
      const next = cuts.filter(c => c > pos);
      let end = next[0];
      let seg = line.slice(pos, end).trim();
      for (let k = next.length - 1; k >= 0; k--) {
        const t = trWhole(line.slice(pos, next[k]).trim(), rule, 0);
        if (t != null) {
          hit = true;
          end = next[k];
          seg = t;
          break;
        }
      }
      if (seg) out.push(seg);
      pos = end;
      while (pos < line.length && line[pos] === " ") pos++;
    }
    return hit ? out.join(" ") : null;
  }

  const active = () => lang !== "ru" && !!compiled;

  /** Translates one finding field (`rule` = provenance.rule); unknown text stays as is. */
  const translate = (text, rule) => {
    if (!active() || !text || typeof text !== "string") return text;
    const key = `${rule}\u0000${text}`;
    if (cache.has(key)) return cache.get(key);
    let out = trWhole(text, rule || "", 0);
    if (out == null)
      out = text
        .split("\n")
        .map(l => trWhole(l, rule || "", 0) ?? trSentences(l, rule || "") ?? l)
        .join("\n");
    if (cache.size > 20000) cache.clear();
    cache.set(key, out);
    return out;
  };

  /** Replaces known core data fragments (`terms`). */
  const terms = s => {
    if (!active() || !s || typeof s !== "string") return s;
    let out = s;
    for (const [ru, tr] of data.terms || []) if (out.includes(ru)) out = out.split(ru).join(tr);
    return out;
  };

  const exact = (table, s) => (active() && s && data[table] && data[table][s]) || s;

  F.ftext = {
    /** Installs the catalog of the UI language (`i18n_bundle().findings`; null for Russian). */
    setCatalog(l, d) {
      lang = l || "ru";
      data = d && typeof d === "object" && Array.isArray(d.catalog) ? d : null;
      compiled = data
        ? data.catalog.map(e => ({ rules: e.rules, toks: tokens(e.pattern), text: e.text }))
        : null;
      cache.clear();
    },
    lang: () => lang,
    active,
    translate,
    terms,
    /** Title / description / evidence of a finding: catalog, then data fragments. */
    field: (text, rule) => terms(translate(text, rule)),
    /** Recommendation (no data fragment replacement, as in reports). */
    recommendation: (text, rule) => translate(text, rule),
    /** A finding source label (`Finding.source`). */
    source: s => exact("sources", s),
    /** A host or person role. */
    role: r => exact("roles", r),
    /**
     * Where a host came from (`Host.source`): a document source label or scan source names joined with ", "
     * (the scan source list of sources.js translates those).
     */
    hostSource: s => {
      if (!active() || !s || typeof s !== "string") return s;
      if (data.host_sources && data.host_sources[s]) return data.host_sources[s];
      const list = F.SOURCE_LIST || [];
      return s
        .split(", ")
        .map(p => {
          if (data.host_sources && data.host_sources[p]) return data.host_sources[p];
          const hit = F.sourceName && list.find(x => x[1] === p);
          return hit ? F.sourceName(hit) : p;
        })
        .join(", ");
    },
    /** A technology category. */
    techCategory: c => (active() ? techCategory(c) : c),
  };
})(typeof window !== "undefined" ? window : globalThis);
