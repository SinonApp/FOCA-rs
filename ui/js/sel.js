/*
 * FOCA-rs selectors: the single source of numbers and relations for all screens.
 * They compute over the F.db snapshot (selectors stay in JS both in demo mode and with the Rust core).
 * Counting rules are documented in docs/API.md ("Selectors").
 */
/*
 * ================= FOCA_RULES: pure, stateless rules (one implementation shared by the UI and the demo
 * backend) =================
 * The demo backend calls the same functions (root.FOCA_RULES), so the scope rule, risk and report selection
 * never diverge.
 * The scope rule matches crates/foca-core/src/scope.rs (see docs/API.md, "Scope rule"):
 * 1. exclusions win over targets; 2. Domain/host covers the domain and all subdomains; Wildcard *.d covers
 * subdomains only;
 * Url covers the exact host only; IP/CIDR/range cover addresses; Org/person/e-mail/ASN grant no host rights;
 * the subdomain boundary is a dot (evilcontoso.ua ∉ contoso.ua);
 * 3. a host name with a known IP (hosts[]) is also checked by IP; excluding a host name also excludes its
 * IPs.
 */
(function (root) {
  // UI dictionary lookup; the bare QA harness and the demo backend may run without core.js (RU fallback).
  const tr = (key, params, fb) => {
    const F0 = typeof window !== "undefined" ? window.FOCA : globalThis.FOCA;
    if (F0 && typeof F0.t === "function") return F0.t(key, params, fb);
    if (typeof params === "string") return params;
    return String(fb).replace(/\{(\w+)\}/g, (_, k) =>
      params && params[k] != null ? String(params[k]) : `{${k}}`,
    );
  };
  const low = s =>
    String(s ?? "")
      .trim()
      .toLowerCase();
  const ip4 = s => {
    const m = String(s)
      .trim()
      .match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m || m.slice(1).some(x => +x > 255)) return null;
    return ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4];
  };
  // Input → host name: lower case, without scheme, port, path or trailing dot; [v6] → v6.
  const normHost = h => {
    let s = low(h).replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
    s = s.split(/[/?#\s]/)[0];
    if (s.startsWith("[")) return s.slice(1, s.indexOf("]") > 0 ? s.indexOf("]") : undefined);
    return s.replace(/:\d+$/, "").replace(/\.$/, "");
  };
  const NET = ["domain", "wild", "url", "ip", "cidr", "range", "host"];
  const RANGE = /^([\d.]+)\s*[-\u2013\u2014]\s*([\d.]+)$/;
  /** Parses a scope entry (target {v, type} or an untyped exclusion string) into a normalized form. */
  function guessType(value) {
    if (/^https?:\/\//.test(value)) return "url";
    if (value.startsWith("*.")) return "wild";
    if (/\/\d{1,2}$/.test(value)) return "cidr";
    if (RANGE.test(value)) return "range";
    if (ip4(value) != null) return "ip";
    if (/^[\p{L}\d-]+(\.[\p{L}\d-]+)+$/u.test(value)) return "domain";
    return "other";
  }
  function entry(v, type) {
    const raw = low(v);
    const kind = type || guessType(raw);
    if (kind === "domain" || kind === "host") return { k: "domain", d: normHost(raw) };
    if (kind === "wild") return { k: "wild", d: normHost(raw.replace(/^\*\./, "")) };
    if (kind === "url") return { k: "url", h: normHost(raw) };
    if (kind === "ip") return { k: "ip", lo: ip4(raw), hi: ip4(raw) };
    if (kind === "cidr") {
      const [base, n] = raw.split("/");
      const addr = ip4(base);
      if (addr == null || +n > 32) return { k: "none" };
      const mask = +n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
      const lo = (addr & mask) >>> 0;
      return { k: "cidr", lo, hi: (lo | (~mask >>> 0)) >>> 0 };
    }
    if (kind === "range") {
      const match = raw.match(RANGE);
      if (!match) return { k: "none" };
      let rangeEnd = match[2];
      if (/^\d{1,3}$/.test(rangeEnd)) rangeEnd = match[1].replace(/\d+$/, rangeEnd);
      const lo = ip4(match[1]),
        hi = ip4(rangeEnd);
      return lo == null || hi == null ? { k: "none" } : { k: "range", lo, hi };
    }
    return { k: "none" }; // org, person, email, asn: grant no rights on hosts.
  }
  const isSub = (h, d) => h.length > d.length + 1 && h.endsWith("." + d);
  const coversName = (e, h) => {
    if (e.k === "domain") return h === e.d || isSub(h, e.d);
    if (e.k === "wild") return isSub(h, e.d);
    if (e.k === "url") return h === e.h;
    return false;
  };
  const coversIp = (e, a) =>
    e.k === "ip" || e.k === "cidr" || e.k === "range"
      ? a >= e.lo && a <= e.hi
      : e.k === "url"
        ? ip4(e.h) === a
        : false;
  const hostIp = x => ip4(String((x && x.ip) || "").split(" ")[0]);
  /**
   * Checks a host or IP (the active phase of the Full profile checks the same way, with no separate
   * permissions).
   * @returns {{ok: boolean, target: ?string, excluded?: string, via?: string, code:
   * ""|"no_host"|"excluded"|"out_of_scope", reason: string}}
   */
  function check(sc, query, opts = {}) {
    sc = sc || {};
    if (!query || query === "-")
      return { ok: false, target: null, code: "no_host", reason: tr("sel.no_host", "нет хоста") };
    const host = normHost(query),
      addr = ip4(host),
      hosts = opts.hosts || [];
    const known = addr == null ? hosts.find(x => low(x.name) === host) : null;
    const ka = known ? hostIp(known) : null;
    const hit = e =>
      addr != null ? coversIp(e, addr) : coversName(e, host) || (ka != null && coversIp(e, ka));
    const ex = (sc.excl || []).map(v => [v, entry(v)]);
    let exHit = ex.find(([, e]) => hit(e)),
      via = null;
    if (!exHit) {
      // Excluding a host name also excludes the known IPs of that host.
      const ipOf = addr != null ? addr : ka;
      if (ipOf != null)
        for (const knownHost of hosts) {
          if (hostIp(knownHost) !== ipOf || low(knownHost.name) === host) continue;
          const hit = ex.find(([, e]) => coversName(e, low(knownHost.name)));
          if (hit) {
            exHit = hit;
            via = knownHost.name;
            break;
          }
        }
    }
    if (exHit)
      return {
        ok: false,
        target: null,
        excluded: exHit[0],
        via,
        code: "excluded",
        reason: via
          ? `${tr("sel.excluded_address_via", { via }, "в исключениях (это адрес {via})")}`
          : tr("sel.excluded", "в исключениях"),
      };
    const t = (sc.targets || []).find(t => hit(entry(t.v, t.type)));
    if (!t)
      return { ok: false, target: null, code: "out_of_scope", reason: tr("sel.out_scope", "нет в скоупе") };
    return { ok: true, target: t.v, code: "", reason: "" };
  }
  /**
   * Checks a whole scope target: domain/URL by name, IP by address, a network unless fully covered by
   * exclusions.
   */
  function checkTarget(sc, target, opts = {}) {
    const parsed = entry(target.v, target.type);
    if (parsed.k === "none")
      return {
        ok: false,
        net: false,
        code: "not_network",
        reason: tr("sel.not_network_target_external", "не сетевая цель: только внешние источники"),
      };
    if (parsed.k === "domain" || parsed.k === "url")
      return { net: true, ...check(sc, parsed.k === "url" ? parsed.h : parsed.d, opts) };
    if (parsed.k === "wild") return { net: true, ...check(sc, "x." + parsed.d, opts) };
    if (parsed.k === "ip") return { net: true, ...check(sc, target.v, opts) };
    const full = (sc.excl || []).find(v => {
      const x = entry(v);
      return (x.k === "cidr" || x.k === "range" || x.k === "ip") && x.lo <= parsed.lo && x.hi >= parsed.hi;
    });
    if (full)
      return {
        ok: false,
        net: true,
        excluded: full,
        code: "excluded",
        reason: tr("sel.network_excluded", "сеть в исключениях"),
      };
    const inList = (sc.targets || []).find(x => low(x.v) === low(target.v));
    if (!inList)
      return { ok: false, net: true, code: "out_of_scope", reason: tr("sel.out_scope", "нет в скоупе") };
    return { ok: true, net: true, target: inList.v, code: "", reason: "" };
  }
  /**
   * Counts excluded addresses of a network target: overlap with excluded networks plus known hosts in the
   * network excluded by name.
   */
  function excludedIn(sc, target, hosts = []) {
    const parsed = entry(target.v, target.type);
    if (!["cidr", "range", "ip"].includes(parsed.k)) return { n: 0, hosts: [] };
    const ranges = (sc.excl || [])
      .map(v => entry(v))
      .filter(x => x.lo != null && x.hi != null && x.hi >= parsed.lo && x.lo <= parsed.hi);
    let n = ranges.reduce((s, x) => s + (Math.min(x.hi, parsed.hi) - Math.max(x.lo, parsed.lo) + 1), 0);
    const hs = hosts.filter(x => {
      const a = hostIp(x);
      return (
        a != null &&
        a >= parsed.lo &&
        a <= parsed.hi &&
        !ranges.some(r => a >= r.lo && a <= r.hi) &&
        (sc.excl || []).some(v => coversName(entry(v), low(x.name)))
      );
    });
    n += new Set(hs.map(hostIp)).size;
    return { n, hosts: hs.map(x => x.name), total: parsed.hi - parsed.lo + 1 };
  }
  const size = t => {
    const e = entry(t.v, t.type);
    return e.lo != null && e.hi != null ? e.hi - e.lo + 1 : 0;
  };
  // ---------- risk, report selection, "has analysis run" ----------
  const SEV_WEIGHT = { crit: 0.25, high: 0.12, warn: 0.05, low: 0.02, info: 0 };
  const SEV_RANK = { crit: 4, high: 3, warn: 2, low: 1, info: 0 };
  const STAGE_IDS = ["search", "download", "meta", "analysis", "network", "ports", "recon", "fuzz", "report"];
  const isLive = f => f.status !== "false" && f.status !== "fixed";
  // Same rule as foca_analysis::findings::risk: findings the core tagged `out_of_scope` (e.g. a Shodan
  // banner of an address outside the scope) are shown but never raise the risk score.
  const outOfScope = f => Array.isArray(f.tags) && f.tags.includes("out_of_scope");
  const riskScore = list =>
    Math.round(
      100 *
        (1 -
          (list || [])
            .filter(f => isLive(f) && !outOfScope(f))
            .reduce((a, f) => a * (1 - (SEV_WEIGHT[f.sev] || 0)), 1)),
    );
  // Findings are counted once a scan has finished, or has been stopped after the Analysis stage.
  const analyzedScans = scans =>
    (scans || []).some(
      s => s.status === "done" || STAGE_IDS.indexOf(s.stage) > STAGE_IDS.indexOf("analysis"),
    );
  /**
   * Report selection.
   * @param {{confirmed?: boolean, min_sev?: string, picked_only?: boolean, picked?: string[]}} o
   * @returns {{main: object[], fixed: object[]}} main excludes false positives and fixed findings.
   */
  function reportSelect(findings, o = {}, picked = []) {
    const fl = findings || [];
    picked = o.picked || picked || [];
    const pass = f =>
      (!o.min_sev || o.min_sev === "all" || SEV_RANK[f.sev] >= SEV_RANK[o.min_sev]) &&
      (!o.picked_only || picked.includes(f.id));
    const bySev = (a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || a.id - b.id;
    return {
      main: fl.filter(f => isLive(f) && (!o.confirmed || f.status === "confirmed") && pass(f)).sort(bySev),
      fixed: fl.filter(f => f.status === "fixed" && pass(f)).sort(bySev),
    };
  }
  // A critical finding that counts for the risk level: live and inside the scope (like the score).
  const hasCrit = list => (list || []).some(f => f.sev === "crit" && isLive(f) && !outOfScope(f));
  // Same scale as foca-report data::risk_level: "Critical" requires ≥90 and at least one critical finding.
  const riskLevel = (score, hasCrit) => {
    if (score == null) return "none";
    if (score >= 90 && hasCrit) return "crit";
    if (score >= 70) return "high";
    if (score >= 40) return "mid";
    return "low";
  };
  root.FOCA_RULES = {
    scope: { entry, check, checkTarget, excludedIn, size, normHost, ip4, coversName, coversIp, NET },
    W: SEV_WEIGHT,
    SEV_RANK,
    STAGE_IDS,
    isLive,
    riskScore,
    riskLevel,
    hasCrit,
    outOfScope,
    analyzedScans,
    reportSelect,
  };
})(typeof window !== "undefined" ? window : globalThis);

(function () {
  const F = window.FOCA;
  // UI dictionary lookup; the bare QA harness and the demo backend may run without core.js (RU fallback).
  const tr = (key, params, fb) => {
    const F0 = typeof window !== "undefined" ? window.FOCA : globalThis.FOCA;
    if (F0 && typeof F0.t === "function") return F0.t(key, params, fb);
    if (typeof params === "string") return params;
    return String(fb).replace(/\{(\w+)\}/g, (_, k) =>
      params && params[k] != null ? String(params[k]) : `{${k}}`,
    );
  };
  const RL = window.FOCA_RULES;
  F.rules = RL;
  // "Today" is the device date; the demo backend lives on a fixed 2026-11-20 (generator data is tied to it).
  const TODAY = (() => {
    if (F.isDemo === false) {
      const d = new Date();
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    }
    return "2026-11-20";
  })();
  const SEV_ORD = ["crit", "high", "warn", "low", "info"];
  const db = () => F.db || {};
  const low = s => String(s ?? "").toLowerCase();
  const uniq = a => [...new Set(a)];
  const isLive = RL.isLive;
  const docsLive = () => (db().docs || []).filter(d => !d.deleted);
  const analyzed = d => (d.status_code || d.status) === "analyzed" || d.status === "Проанализирован";

  // ---------- scans ----------
  const scans = () => db().scans || [];
  const lastScan = () => {
    const s = scans();
    return s.length ? s[s.length - 1] : null;
  };
  const prevScan = () => {
    const s = scans().filter(x => x.status === "done");
    return s.length > 1 ? s[s.length - 2] : null;
  };

  // ---------- scope: a single FOCA_RULES.scope rule (also used by the demo backend) ----------
  const SR = RL.scope,
    NET_T = SR.NET;
  const sc0 = s => s || db().scope || {};
  const opt = () => ({ hosts: db().hosts || [], today: TODAY });
  // `scope` is an optional scope object (the new-project draft in the wizard); defaults to the current
  // project's scope.
  const check = (hostOrIp, scope) => SR.check(sc0(scope), hostOrIp, opt());
  const scope = {
    check,
    allows: h => check(h).ok,
    today: TODAY,
    checkTarget: (t, scope) => SR.checkTarget(sc0(scope), t, opt()),
    excludedIn: (t, scope) => SR.excludedIn(sc0(scope), t, db().hosts || []),
    info(scope) {
      const sc = sc0(scope);
      const net = (sc.targets || []).filter(t => NET_T.includes(t.type));
      // Active-phase targets of the Full profile: all network targets in scope (exclusions are checked per
      // request).
      return {
        ...sc,
        nTargets: (sc.targets || []).length,
        nNet: net.length,
        nExcl: (sc.excl || []).length,
        activeTargets: net.map(t => t.v),
      };
    },
  };

  // ---------- counts ----------
  function counts() {
    const data = db(),
      docs = docsLive(),
      an = docs.filter(analyzed);
    const last = lastScan(),
      prev = prevScan();
    const fl = data.findings || [];
    const nf = fl.filter(f => f.status !== "false");
    const live = fl.filter(isLive);
    const bySev = Object.fromEntries(SEV_ORD.map(s => [s, live.filter(f => f.sev === s).length]));
    return {
      docs: {
        total: docs.length,
        downloaded: docs.filter(x => ["analyzed", "downloaded"].includes(x.status_code)).length,
        analyzed: an.length,
        with_findings: an.filter(x => (x.findings || []).some(k => k !== "eol")).length,
        deleted: (data.docs || []).length - docs.length,
        new: last && prev ? docs.filter(x => x.first_scan === last.id).length : 0,
        queued: docs.filter(x => x.status_code === "queued").length,
        error: docs.filter(x => x.status_code === "error").length,
      },
      people: {
        total: (data.people || []).length,
        meta: (data.people || []).filter(p => p.src_kind === "meta").length,
        text: (data.people || []).filter(p => p.src_kind === "text").length,
      },
      emails: {
        total: (data.emails || []).length,
        found: (data.emails || []).filter(e => e.found).length,
        personal: (data.emails || []).filter(e => !e.role).length,
      },
      hosts: {
        total: (data.hosts || []).length,
        internal: (data.hosts || []).filter(h => h.internal).length,
        external: (data.hosts || []).filter(h => !h.internal).length,
      },
      software: { total: (data.software || []).length, eol: (data.software || []).filter(s => s.eol).length },
      secrets: (data.secrets || []).length,
      pcs: (data.pcs || []).length,
      paths: (data.paths || []).length,
      printers: (data.printers || []).length,
      gps: (data.gps || []).length,
      findings: {
        ...bySev,
        total: nf.length,
        open: live.length,
        confirmed: fl.filter(f => f.status === "confirmed").length,
        fresh: fl.filter(f => f.status === "new").length,
        new_since_last: last && prev ? nf.filter(f => f.first_scan === last.id).length : 0,
        fixed: fl.filter(f => f.status === "fixed").length,
        false: fl.filter(f => f.status === "false").length,
        all: fl.length,
      },
      scans: scans().length,
    };
  }
  function risk(list) {
    // No data until at least one scan has passed the Analysis stage; `list` is a custom selection (report
    // risk over included findings).
    if (!scans().length)
      return {
        score: null,
        level: "none",
        label: tr("projects.no_data", "нет данных"),
        title: tr("projects.never_scanned", "Скан не запускался"),
        cls: "none",
        icon: "dot",
      };
    if (!list && !RL.analyzedScans(scans()))
      return {
        score: null,
        level: "none",
        label: tr("projects.no_data", "нет данных"),
        title: tr("sel.findings_not_analyzed_yet", "Находки ещё не анализировались"),
        cls: "none",
        icon: "dot",
      };
    const score = RL.riskScore(list || db().findings || []);
    return score >= 70
      ? {
          score,
          level: "high",
          label: tr("projects.high", "высокий"),
          title: tr("sel.high_leak_risk", "Высокий риск утечки"),
          cls: "crit",
          icon: "alert",
        }
      : score >= 40
        ? {
            score,
            level: "mid",
            label: tr("projects.medium", "средний"),
            title: tr("sel.medium_risk", "Средний риск"),
            cls: "warn",
            icon: "info",
          }
        : {
            score,
            level: "low",
            label: tr("projects.low", "низкий"),
            title: tr("sel.low_risk", "Низкий риск"),
            cls: "ok",
            icon: "check",
          };
  }

  // ---------- entities and relations (built from the data) ----------
  function entity(type, id) {
    const data = db();
    const sid = String(id);
    switch (type) {
      case "person":
        return (data.people || []).find(p => p.login === sid) || null;
      case "host":
        return (data.hosts || []).find(h => low(h.name) === low(sid)) || null;
      case "pc":
        return (data.pcs || []).find(p => p.name === sid) || null;
      case "software":
        return (
          (data.software || []).find(s => s.id === sid) ||
          (/^\d+$/.test(sid) ? (data.software || [])[+sid] : null) ||
          null
        );
      case "printer":
        return (
          (data.printers || []).find(p => p.name === sid) ||
          (/^\d+$/.test(sid) ? (data.printers || [])[+sid] : null) ||
          null
        );
      case "path":
        return (
          (data.paths || []).find(p => p.path === sid) ||
          (/^\d+$/.test(sid) ? (data.paths || [])[+sid] : null) ||
          null
        );
      case "email":
        return (data.emails || []).find(e => e.addr === sid) || null;
      case "doc":
        return (data.docs || []).find(x => x.id === +sid && !x.deleted) || null;
      case "finding":
        return (data.findings || []).find(f => f.id === +sid) || null;
      case "secret":
        return (data.secrets || []).find(s => s.id === +sid) || null;
      default:
        return null;
    }
  }
  const authorOf = doc =>
    (db().people || []).find(p => p.login === (doc.author || (doc.user && doc.user.login)));
  const docsOfPc = name =>
    docsLive().filter(x => {
      const a = authorOf(x);
      return (
        (a && a.pc === name) ||
        (x.folder || "").includes(name) ||
        (x.printer || "").includes(name) ||
        (x.rdp && x.rdp.gateway === name) ||
        (x.lnk && x.lnk.machine === name)
      );
    });
  function related(type, id) {
    const data = db(),
      ent = entity(type, id);
    const rel = {
      docs: [],
      people: [],
      pcs: [],
      hosts: [],
      software: [],
      findings: [],
      emails: [],
      secrets: [],
      printers: [],
      paths: [],
    };
    if (!ent) return rel;
    const docSet = list => {
      rel.docs = list;
      const ids = new Set(list.map(x => x.id));
      rel.secrets = (data.secrets || []).filter(s => ids.has(s.doc));
      return ids;
    };
    const fromDocs = list => {
      rel.people = uniq(list.map(x => x.author).filter(Boolean))
        .map(l => entity("person", l))
        .filter(Boolean);
      rel.software = uniq(list.map(x => x.software).filter(Boolean))
        .map(s => entity("software", s))
        .filter(Boolean);
      rel.hosts = uniq(list.map(x => x.host))
        .map(h => entity("host", h))
        .filter(Boolean);
      rel.printers = uniq(list.map(x => x.printer).filter(x => x && x !== "-"))
        .map(p => entity("printer", p))
        .filter(Boolean);
      rel.paths = uniq(list.map(x => x.folder).filter(x => x && x !== "-"))
        .map(p => entity("path", p))
        .filter(Boolean);
      rel.pcs = uniq(rel.people.map(p => p.pc).filter(x => x && x !== "-"))
        .map(p => entity("pc", p))
        .filter(Boolean);
    };
    if (type === "person") {
      const ids = docSet(docsLive().filter(x => x.author === ent.login));
      fromDocs(rel.docs);
      rel.people = [];
      rel.pcs = ent.pc && ent.pc !== "-" && entity("pc", ent.pc) ? [entity("pc", ent.pc)] : [];
      rel.findings = (data.findings || []).filter(
        f => (f.rel.people || []).includes(ent.login) || (f.doc && ids.has(f.doc)),
      );
      rel.emails = (data.emails || []).filter(m => m.login === ent.login);
    } else if (type === "host") {
      const ids = docSet(docsLive().filter(x => low(x.host) === low(ent.name)));
      fromDocs(rel.docs);
      rel.hosts = [];
      rel.findings = (data.findings || []).filter(
        f => low(f.host) === low(ent.name) || (f.rel.pcs || []).includes(ent.name),
      );
      rel.secrets = rel.secrets.concat(
        (data.secrets || []).filter(s => s.host === ent.name && !ids.has(s.doc)),
      );
      rel.pcs = (data.pcs || []).filter(p => p.name === ent.name);
    } else if (type === "pc") {
      docSet(docsOfPc(ent.name));
      fromDocs(rel.docs);
      rel.people = (ent.users || []).map(l => entity("person", l)).filter(Boolean);
      rel.pcs = [];
      rel.findings = (data.findings || []).filter(f => (f.rel.pcs || []).includes(ent.name));
      rel.hosts = (data.hosts || []).filter(h => h.name === ent.name);
    } else if (type === "software") {
      const ids = docSet(docsLive().filter(x => x.software === ent.id));
      fromDocs(rel.docs);
      rel.software = [];
      rel.findings = (data.findings || []).filter(f => f.category === "sw" && f.doc && ids.has(f.doc));
    } else if (type === "printer") {
      docSet(docsLive().filter(x => x.printer === ent.name));
      fromDocs(rel.docs);
      rel.printers = [];
      rel.hosts = ent.host ? (data.hosts || []).filter(h => h.name === ent.host) : [];
    } else if (type === "path") {
      docSet(docsLive().filter(x => x.folder === ent.path));
      fromDocs(rel.docs);
      rel.paths = [];
      if (ent.user && !rel.people.some(p => p.login === ent.user) && entity("person", ent.user))
        rel.people.unshift(entity("person", ent.user));
      rel.hosts = ent.host ? (data.hosts || []).filter(h => h.name === ent.host) : [];
    } else if (type === "email") {
      const person = ent.login ? entity("person", ent.login) : null;
      rel.people = person ? [person] : [];
      rel.findings = (data.findings || []).filter(
        f => ent.login && (f.rel.people || []).includes(ent.login) && f.category === "people",
      );
      rel.docs = person ? docsLive().filter(x => x.author === person.login) : [];
    } else if (type === "doc") {
      const author = authorOf(ent);
      rel.people = author ? [author] : [];
      rel.software = ent.software ? [entity("software", ent.software)].filter(Boolean) : [];
      rel.hosts = [entity("host", ent.host)].filter(Boolean);
      rel.findings = (data.findings || []).filter(
        f => f.doc === ent.id || (f.rel.docs || []).includes(ent.id),
      );
      rel.secrets = (data.secrets || []).filter(s => s.doc === ent.id);
      rel.printers =
        ent.printer && ent.printer !== "-" ? [entity("printer", ent.printer)].filter(Boolean) : [];
      rel.paths = ent.folder && ent.folder !== "-" ? [entity("path", ent.folder)].filter(Boolean) : [];
      rel.pcs = author && author.pc && author.pc !== "-" ? [entity("pc", author.pc)].filter(Boolean) : [];
      rel.docs = author ? docsLive().filter(x => x.author === author.login && x.id !== ent.id) : [];
    } else if (type === "finding") {
      rel.docs = (ent.rel.docs || []).map(i => entity("doc", i)).filter(Boolean);
      rel.people = (ent.rel.people || []).map(l => entity("person", l)).filter(Boolean);
      rel.pcs = (ent.rel.pcs || []).map(n => entity("pc", n)).filter(Boolean);
      rel.hosts = [entity("host", ent.host)].filter(Boolean);
    }
    return rel;
  }

  // ---------- search across all entities ----------
  const KINDS = ["findings", "docs", "people", "hosts", "emails", "software", "pcs", "secrets"];
  function search(query, kinds = KINDS) {
    const data = db();
    query = low(query).trim();
    const out = Object.fromEntries(KINDS.map(k => [k, []]));
    if (!query) return out;
    const has = (...xs) => xs.some(x => low(Array.isArray(x) ? x.join(" ") : x).includes(query));
    const on = k => kinds.includes(k);
    if (on("findings"))
      out.findings = (data.findings || []).filter(f =>
        has(f.title, f.host, f.source, f.cve, f.tags, f.description),
      );
    if (on("docs")) out.docs = docsLive().filter(x => has(x.name, x.author, x.host, x.user && x.user.name));
    if (on("people")) out.people = (data.people || []).filter(p => has(p.name, p.login, p.role));
    if (on("hosts")) out.hosts = (data.hosts || []).filter(h => has(h.name, h.ip, h.tech, h.role));
    if (on("emails")) out.emails = (data.emails || []).filter(e => has(e.addr, e.name, e.src));
    if (on("software")) out.software = (data.software || []).filter(s => has(s.name, s.ver));
    if (on("pcs")) out.pcs = (data.pcs || []).filter(p => has(p.name, p.ip));
    if (on("secrets")) out.secrets = (data.secrets || []).filter(s => has(s.where, s.host, s.type));
    out.total = KINDS.reduce((a, k) => a + out[k].length, 0);
    return out;
  }

  // ---------- timeline ----------
  function timeline() {
    const docs = docsLive().filter(x => analyzed(x) && x.year);
    const years = uniq(docs.map(x => x.year)).sort((a, b) => a - b);
    const byYear = Object.fromEntries(years.map(y => [y, docs.filter(x => x.year === y).length]));
    const wh = (db().settings || {}).work_hours || { from: 8, to: 19 };
    return { docs, years, byYear, events: db().events || [], workHours: wh };
  }

  // ---------- diff of two scans (from snapshots) ----------
  const SEVL = () => ({
    crit: tr("sev.crit", "Критический"),
    high: tr("sev.high", "Высокий"),
    warn: tr("sev.warn", "Средний"),
    low: tr("sev.low", "Низкий"),
    info: tr("sev.info", "Инфо"),
  });
  function diff(a, b) {
    const sc = scans();
    const pick = x => (typeof x === "number" ? sc[x] : sc.find(s => s.id === x));
    const snapA = pick(a),
      snapB = pick(b);
    const items = [];
    if (!snapA || !snapB || !snapA.snapshot || !snapB.snapshot)
      return {
        a: snapA,
        b: snapB,
        items,
        counts: { "+": 0, "-": 0, "~": 0 },
        incomplete: false,
        incomplete_reasons: [],
      };
    const envB = snapB.env || {};
    const incompleteReasons =
      Array.isArray(envB.incomplete_sources) && envB.incomplete_sources.length
        ? envB.incomplete_sources.slice()
        : Array.isArray(snapB.incomplete)
          ? snapB.incomplete.slice()
          : [];
    if (envB.tcp_intercept) incompleteReasons.push("tcp_intercept");
    if (envB.dns_hijack) incompleteReasons.push("dns_hijack");
    if (envB.tls_mitm) incompleteReasons.push("tls_mitm");
    const incomplete = Boolean(
      envB.incomplete ||
      (Array.isArray(snapB.incomplete) && snapB.incomplete.length) ||
      snapB.status === "stopped",
    );
    const sa = snapA.snapshot,
      sb = snapB.snapshot,
      data = db();
    const ia = new Set(sa.docs),
      ib = new Set(sb.docs);
    sb.docs
      .filter(i => !ia.has(i))
      .forEach(i => {
        const x = (data.docs || []).find(y => y.id === i);
        if (x && !x.deleted)
          items.push({
            g: "docs",
            k: "+",
            t: x.name,
            s: `${x.host}${x.author ? " · " + x.author : tr("sel.no_metadata", " · без метаданных")}${(x.findings || []).includes("secret") ? tr("sel.secret_text", " · секрет в тексте") : ""}`,
            sev: (x.findings || []).includes("secret") ? "crit" : "",
            ref: { type: "doc", id: i },
          });
      });
    if (!incomplete) {
      sa.docs
        .filter(i => !ib.has(i))
        .forEach(i => {
          const x = (data.docs || []).find(y => y.id === i);
          items.push({
            g: "docs",
            k: "-",
            t: x ? x.name : `${tr("sel.document", "Документ #")}${i}`,
            s: tr("sel.no_longer_found_site", "Больше не найден на сайте"),
            ref: { type: "doc", id: i },
          });
        });
    }
    Object.keys(sb.hosts).forEach(hostName => {
      if (!(hostName in sa.hosts)) {
        const hostEnt = entity("host", hostName);
        items.push({
          g: "hosts",
          k: "+",
          t: hostName,
          s: hostEnt ? `${hostEnt.ip} · ${hostEnt.role}` : "",
          sev: hostEnt && hostEnt.sev === "crit" ? "crit" : "",
          ref: { type: "host", id: hostName },
        });
      } else if (sa.hosts[hostName] !== sb.hosts[hostName])
        items.push({
          g: "hosts",
          k: "~",
          t: hostName,
          s: tr("sel.software_fingerprint_changed", "Изменился отпечаток ПО"),
          was: sa.hosts[hostName],
          now: sb.hosts[hostName],
          ref: { type: "host", id: hostName },
        });
    });
    if (!incomplete) {
      Object.keys(sa.hosts).forEach(h => {
        if (!(h in sb.hosts))
          items.push({
            g: "hosts",
            k: "-",
            t: h,
            s: tr("sel.no_longer_responds_not_dns", "Больше не отвечает / нет в DNS"),
          });
      });
    }
    const pa = new Set(sa.people),
      pb = new Set(sb.people);
    sb.people
      .filter(l => !pa.has(l))
      .forEach(l => {
        const p = entity("person", l);
        items.push({
          g: "people",
          k: "+",
          t: p ? p.name : l,
          s: `${l} ${tr("sel.new_document_author", "· новый автор документов")}`,
          ref: { type: "person", id: l },
        });
      });
    if (!incomplete) {
      sa.people
        .filter(l => !pb.has(l))
        .forEach(l => {
          const p = entity("person", l);
          items.push({
            g: "people",
            k: "-",
            t: p ? p.name : l,
            s: `${l} ${tr("sel.not_among_document_authors", "· нет среди авторов документов")}`,
          });
        });
    }
    Object.keys(sb.findings).forEach(id => {
      const finding = entity("finding", id);
      if (!(id in sa.findings))
        items.push({
          g: "finds",
          k: "+",
          t: finding ? finding.title : `${tr("sel.finding", "Находка #")}${id}`,
          s: finding ? finding.host : "",
          sev: sb.findings[id],
          ref: { type: "finding", id: +id },
        });
      else if (sa.findings[id] !== sb.findings[id])
        items.push({
          g: "finds",
          k: "~",
          t: finding ? finding.title : id,
          s: finding ? finding.host : "",
          was: SEVL()[sa.findings[id]],
          now: SEVL()[sb.findings[id]],
          ref: { type: "finding", id: +id },
        });
    });
    if (!incomplete) {
      Object.keys(sa.findings).forEach(id => {
        if (!(id in sb.findings)) {
          const f = entity("finding", id);
          items.push({
            g: "finds",
            k: "-",
            t: f ? f.title : `${tr("sel.finding", "Находка #")}${id}`,
            s: tr("sel.not_reproduced_probably_fixed", "Не воспроизводится: вероятно, исправлено"),
            ref: { type: "finding", id: +id },
          });
        }
      });
    }
    // Site technologies (recon): added, removed and version-changed.
    const ta = sa.tech || {},
      tb = sb.tech || {},
      tv = v => (v ? " " + v : "");
    Object.keys(tb).forEach(n => {
      if (!(n in ta))
        items.push({
          g: "tech",
          k: "+",
          t: n + tv(tb[n]),
          s: tr("sel.new_technology_site", "Новая технология на сайте"),
        });
      else if (ta[n] !== tb[n])
        items.push({
          g: "tech",
          k: "~",
          t: n,
          s: `${ta[n] || tr("sel.version_unknown", "версия не определена")} → ${tb[n] || tr("sel.version_unknown", "версия не определена")}`,
        });
    });
    if (!incomplete) {
      Object.keys(ta).forEach(n => {
        if (!(n in tb))
          items.push({
            g: "tech",
            k: "-",
            t: n + tv(ta[n]),
            s: tr("sel.no_longer_detected_site", "Больше не определяется на сайте"),
          });
      });
    }
    const counts = { "+": 0, "-": 0, "~": 0 };
    items.forEach(i => counts[i.k]++);
    return { a: snapA, b: snapB, items, counts, incomplete, incomplete_reasons: incompleteReasons };
  }

  // ---------- relation graph ----------
  let GC = null,
    GDB = null;
  function graphAll() {
    if (GC && GDB === F.db) return GC;
    const data = db(),
      nodes = new Map(),
      adj = new Map();
    const key = (t, id) => `${t}:${id}`;
    const add = (t, id, o) => {
      const k = key(t, id);
      if (!nodes.has(k)) nodes.set(k, { k, type: t, id: String(id), ...o });
      return k;
    };
    const link = (a, b, w = 1) => {
      if (!a || !b || a === b) return;
      for (const [x, y] of [
        [a, b],
        [b, a],
      ]) {
        if (!adj.has(x)) adj.set(x, new Map());
        adj.get(x).set(y, (adj.get(x).get(y) || 0) + w);
      }
    };
    (data.hosts || []).forEach(h => add("host", h.name, { label: h.name, data: h }));
    (data.pcs || []).forEach(p => {
      if (!nodes.has(key("host", p.name))) add("pc", p.name, { label: p.name, data: p });
    });
    const pcK = n =>
      nodes.has(key("host", n)) ? key("host", n) : nodes.has(key("pc", n)) ? key("pc", n) : null;
    (data.software || []).forEach(s => add("software", s.id, { label: s.name, data: s }));
    (data.people || []).forEach(p => {
      const k = add("person", p.login, { label: p.name, data: p });
      if (p.pc && p.pc !== "-") link(k, pcK(p.pc), 3);
    });
    docsLive()
      .filter(analyzed)
      .forEach(x => {
        const k = add("doc", x.id, { label: x.name, data: x });
        const pk = x.author && nodes.has(key("person", x.author)) ? key("person", x.author) : null,
          sk = x.software ? key("software", x.software) : null,
          hk = nodes.has(key("host", x.host)) ? key("host", x.host) : null;
        link(k, pk);
        link(k, sk);
        link(k, hk);
        link(pk, sk);
        link(pk, hk);
        [x.folder, x.printer].forEach(v => {
          const m = String(v || "").match(/^\\\\([^\\]+)/);
          if (m && pcK(m[1])) link(k, pcK(m[1]));
        });
      });
    // Hosts/PCs known from outside metadata (a connection string in a secret, AXFR in a finding) are
    // relations too.
    (data.secrets || []).forEach(s => {
      const hk = s.host && pcK(s.host),
        dk = key("doc", s.doc);
      if (hk && nodes.has(dk)) link(dk, hk);
    });
    (data.findings || [])
      .filter(f => f.status !== "false")
      .forEach(f => {
        const r = f.rel || {};
        const fh = f.host && pcK(f.host);
        (r.pcs || []).forEach(pc => {
          const pk = pcK(pc);
          if (!pk) return;
          link(pk, fh);
          (r.docs || []).forEach(id => {
            if (nodes.has(key("doc", id))) link(pk, key("doc", id));
          });
          (r.people || []).forEach(l => {
            if (nodes.has(key("person", l))) link(pk, key("person", l));
          });
        });
      });
    GDB = F.db;
    GC = { N: nodes, A: adj, key };
    return GC;
  }
  function graph(type, id) {
    const g = graphAll();
    const k = g.key(type, id);
    if (!g.N.has(k)) return null;
    const nb = [...(g.A.get(k) || new Map()).entries()].map(([kk, w]) => ({ ...g.N.get(kk), w }));
    return { node: g.N.get(k), neighbors: nb, has: kk => g.N.has(kk), all: g };
  }

  // ---------- operating systems, derived from document metadata ----------
  // Application/Producer of office and PDF files → Windows; LibreOffice → Linux; EXIF Software of phones →
  // iOS/Android;
  // scanner and camera firmware separately; .lnk → Windows (shortcut), .rdp → Windows Server (terminal
  // server).
  const OS_BY_SW = sw => {
    if (!sw) return null;
    if (/^(word|excel|ppt|acro|pdflib|ps)/.test(sw.id))
      return ["Microsoft Windows", "windows", "Application / Producer"];
    if (sw.id === "lo72") return ["Linux", "linux", "Application (LibreOffice)"];
    if (/^ios/.test(sw.id)) return [sw.name, "ios", "EXIF Software"];
    if (/^android/.test(sw.id)) return [sw.name.replace(/\s*\(.*\)/, ""), "android", "EXIF Software"];
    if (sw.kind === "scanner")
      return [
        `${tr("sel.mfp_firmware_name", { name: sw.name.split(" ")[0] }, "Прошивка МФУ ({name})")}`,
        "embedded",
        "PDF Producer",
      ];
    if (sw.kind === "camera")
      return [
        `${tr("sel.camera_firmware_name", { name: sw.name.split(" ")[0] }, "Прошивка камеры ({name})")}`,
        "embedded",
        "EXIF Software",
      ];
    return null;
  };
  function os() {
    const byName = new Map();
    const swBy = Object.fromEntries((db().software || []).map(s => [s.id, s]));
    const add = (name, family, src, d) => {
      const k = name;
      const found = byName.get(k) || {
        id: low(name)
          .replace(/[^a-zа-я0-9]+/gi, "-")
          .replace(/^-|-$/g, ""),
        name,
        family,
        src: [],
        docs: 0,
        doc_ids: [],
      };
      if (!found.src.includes(src)) found.src.push(src);
      found.docs++;
      found.doc_ids.push(d.id);
      byName.set(k, found);
    };
    docsLive()
      .filter(analyzed)
      .forEach(d => {
        if (d.ext === "lnk")
          return add("Microsoft Windows", "windows", tr("sel.lnk_shortcut", "Ярлык .lnk"), d);
        if (d.ext === "rdp") return add("Windows Server", "windows", tr("sel.rdp_file", "Файл .rdp"), d);
        const o = OS_BY_SW(swBy[d.software]);
        if (o) add(o[0], o[1], o[2], d);
      });
    return [...byName.values()].sort((a, b) => b.docs - a.docs);
  }

  // ---------- findings selection for reports (one rule for the builder, the preview and the history)
  // ----------
  function reportPicked() {
    const p = (((db().settings || {}).report || {}).picked || {})[(db().project || {}).id] || [];
    const ids = new Set((db().findings || []).map(f => f.id));
    return p.filter(id => ids.has(id));
  }
  // o: { confirmed, min_sev: "all"|"low"|…, picked_only, picked: id[] } → { main: current findings (no false
  // positives or fixed), fixed: fixed findings }.
  // The core applies the same FOCA_RULES.reportSelect rule in report_build (report result snapshot).
  const reportFindings = (o = {}) => RL.reportSelect(db().findings || [], o, o.picked || reportPicked());

  // ---------- scanner request log: the actual record count from the core (request_log_get) ----------
  // Until the core answers, total is null (the UI shows "-"); no formula-based estimates. Re-read when the
  // project
  // or the scan list changes; re-render only if the number changed (the demo backend is synchronous).
  const RQ = { key: null, total: null, sample: [], by_scan: [] };
  function requests() {
    const project = db().project,
      sc = scans(),
      last = lastScan();
    const key = project
      ? `${project.id}|${sc.length}|${last ? last.id + ":" + (last.status || "") + ":" + (last.finished_at || "") : ""}`
      : "";
    if (key !== RQ.key) {
      RQ.key = key;
      RQ.total = null;
      RQ.sample = [];
      RQ.by_scan = [];
      if (project && F.api && F.api.request_log_get) {
        Promise.resolve()
          .then(() => F.api.request_log_get({ project: project.id, limit: 1e9 }))
          .then(
            v => {
              if (RQ.key !== key || !Array.isArray(v)) return;
              const by = {};
              v.forEach(r => {
                by[r.scan_id] = (by[r.scan_id] || 0) + 1;
              });
              const changed = RQ.total !== v.length;
              RQ.total = v.length;
              RQ.by_scan = Object.entries(by).map(([id, n]) => ({ id, n }));
              RQ.sample = v
                .slice(0, 3)
                .map(
                  r =>
                    `${F.fmt && F.fmt.dmyhm ? F.fmt.dmyhm(r.time) : r.time} ${r.method} ${r.url} ${r.status || "-"}`,
                );
              if (changed && F.render) F.render(true);
            },
            () => {},
          );
      }
    }
    return { total: RQ.total, by_scan: RQ.by_scan, sample: RQ.sample };
  }

  F.sel = {
    counts,
    risk,
    scope,
    entity,
    related,
    search,
    timeline,
    diff,
    graph,
    graphAll,
    scans,
    lastScan,
    prevScan,
    docsLive,
    isLive,
    SEV_ORD,
    KINDS,
    os,
    reportPicked,
    reportFindings,
    requests,
  };
  // Reset the graph cache when data changes.
  if (F.on)
    F.on("db", () => {
      GC = null;
    });
  // Demo: the first snapshot load needs the rules (the demo backend counts out-of-scope candidates with
  // FOCA_RULES), so it is started here, synchronously, before screens are loaded (api.js left F._bootDemo).
  if (F._bootDemo) {
    const bootDemo = F._bootDemo;
    delete F._bootDemo;
    bootDemo();
  }
})();
