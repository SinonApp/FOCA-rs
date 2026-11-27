// Analytics (docs/API.md → "Аналитика"): the layered link graph with layer filters, clusters
// and the "link chain" mode (/p/graph), the internal network map (/p/netmap), year lanes and the 7×24 heat
// map for /p/timeline, the org chart (people and overview), anomaly / KEV / lineage blocks for findings and
// documents, and the web audit blocks for hosts and findings (snapshot recon.web[]).
// Data: insights_get (cached per project and arguments, dropped on any data change) and chain_get.
(function () {
  // Core texts (anomalies, web audit issues, attack paths) in the UI language by their finding rule; an empty rule
  // matches any catalog template (attack path steps repeat finding titles).
  const ftx = (t, rule) => (F.ftext && t ? F.ftext.field(t, rule) : t);
  // Attack path title: a catalog template, or "<finding title> → <host>".
  const apTitle = t => {
    const tr = ftx(t, "");
    const i = t.lastIndexOf(" → ");
    return tr !== t || i < 0 ? tr : `${ftx(t.slice(0, i), "")} → ${t.slice(i + 3)}`;
  };
  const F = window.FOCA,
    { ic, esc, ui } = F;
  // Language-aware: Slavic 1/2-4/5+ forms for ru/uk, one/other for English.
  const plural = (n, a, b, c) => F.plural(n, a, b, c);
  // Label tables keep Russian fallbacks and are translated on read with the key "<prefix>.<key>": `pos` is the
  // label index inside array values ("all" = every item, e.g. plural forms); list tables (arrays of tuples)
  // are keyed by the tuple id (item 0).
  const tt = (prefix, table, pos = 0) =>
    new Proxy(table, {
      get: (o, k) => {
        const v = o[k];
        if (typeof k !== "string" || k === "length" || !Object.prototype.hasOwnProperty.call(o, k)) return v;
        const key = `${prefix}.${Array.isArray(o) ? v[0] : k}`;
        if (!Array.isArray(v)) return typeof v === "string" ? F.t(key, v) : v;
        if (pos === "all") return v.map((x, i) => F.t(`${key}.${i}`, x));
        return v.map((x, i) => (i === pos ? F.t(key, x) : x));
      },
    });

  // ================= data =================
  // The demo backend answers synchronously but through a promise: the cache makes the follow-up render a hit,
  // so a screen never loops; a failed call (an older core) is cached as an empty answer.
  const CACHE = new Map();
  const PENDING = new Set();
  const AP_CACHE = new Map();
  const AP_PENDING = new Set();
  const pid = () => (F.db && F.db.project && F.db.project.id) || "";
  function load(args) {
    const p = pid();
    if (!p || !F.api.insights_get) return null;
    const key = p + "|" + JSON.stringify(args || {});
    if (CACHE.has(key)) return CACHE.get(key);
    if (!PENDING.has(key)) {
      PENDING.add(key);
      F.api.insights_get(args || {}).then(
        r => {
          PENDING.delete(key);
          CACHE.set(key, r || {});
          if (pid() === p) F.render(true);
        },
        e => {
          PENDING.delete(key);
          CACHE.set(key, { error: (e && e.message) || String(e) });
          if (pid() === p) F.render(true);
        },
      );
    }
    return null;
  }
  function loadAttackPaths() {
    const p = pid();
    if (!p || !F.api || !F.api.attack_paths_get) return null;
    if (AP_CACHE.has(p)) return AP_CACHE.get(p);
    if (!AP_PENDING.has(p)) {
      AP_PENDING.add(p);
      F.api.attack_paths_get().then(
        r => {
          AP_PENDING.delete(p);
          AP_CACHE.set(p, r || { paths: [], choke_points: [], summary: {} });
          if (pid() === p) F.render(true);
        },
        e => {
          AP_PENDING.delete(p);
          AP_CACHE.set(p, { error: (e && e.message) || String(e), paths: [], choke_points: [], summary: {} });
          if (pid() === p) F.render(true);
        },
      );
    }
    return null;
  }
  const ins = () => load({});
  F.on("db", e => {
    if (e && e.kind !== "infra" && e.kind !== "settings") {
      CACHE.clear();
      AP_CACHE.clear();
      if (e.kind === "project" || e.kind === "reset") resetGraph();
    }
  });

  // ================= labels =================
  const KIND = tt(
    "insights.kind",
    {
      person: ["user", "Человек"],
      email: ["mail", "E-mail"],
      doc: ["doc", "Документ"],
      pc: ["monitor", "Рабочая станция"],
      workstation: ["monitor", "Рабочая станция"],
      host: ["server", "Сервер"],
      server: ["server", "Сервер"],
      printer: ["printer", "Принтер"],
      share: ["folder", "Сетевая папка"],
      domain: ["domain", "Домен AD"],
      forest: ["domain", "Лес AD"],
      pki: ["lock", "PKI / УЦ"],
      ca: ["lock", "Удостоверяющий центр"],
      software: ["app", "Программа"],
      user: ["user", "Пользователь"],
    },
    1,
  );
  const kindIc = k => (KIND[k] || ["dot"])[0];
  const kindLabel = k => (KIND[k] || [null, k])[1];
  const VIA = tt("insights.via", {
    author: "автор",
    last_modified_by: "изменял",
    created_by: "автор",
    uses_pc: "работает на ПК",
    created_on: "создан на ПК",
    created_with: "создан в программе",
    printed_on: "печать на",
    on_host: "расположен на сервере",
    member_of: "входит в домен",
    path: "путь к файлу",
    share: "сетевая папка",
    in_share: "в сетевой папке",
    email: "e-mail",
    has_email: "e-mail",
    derived_from: "создан из",
    copy: "копия",
    same_lineage: "одна линия версий",
    issued_by: "выпущен УЦ",
    cdp: "список отзыва (CDP)",
    aia: "адрес УЦ (AIA)",
    mentions: "упоминает",
    link: "ссылка",
  });
  const viaLabel = v => VIA[v] || String(v || "").replace(/_/g, " ");
  const LAYERS = tt(
    "insights.layer",
    [
      ["people", "Люди", "users"],
      ["docs", "Документы", "doc"],
      ["pcs", "ПК", "monitor"],
      ["servers", "Серверы", "server"],
      ["pki_domains", "PKI/Домены", "domain"],
    ],
    1,
  );
  const GROUP_WORDS = tt(
    "insights.group",
    {
      person: ["человек", "человека", "человек"],
      email: ["адрес", "адреса", "адресов"],
      doc: ["документ", "документа", "документов"],
      pc: ["ПК", "ПК", "ПК"],
      host: ["сервер", "сервера", "серверов"],
      printer: ["принтер", "принтера", "принтеров"],
      share: ["папка", "папки", "папок"],
      domain: ["домен", "домена", "доменов"],
      pki: ["УЦ", "УЦ", "УЦ"],
      software: ["программа", "программы", "программ"],
    },
    "all",
  );
  const groupLabel = n =>
    plural(
      n.count || 0,
      ...(GROUP_WORDS[n.kind] || [
        F.t("insights.node", "узел"),
        F.t("insights.node_few", "узла"),
        F.t("insights.node_many", "узлов"),
      ]),
    );
  // Route of the existing entity cards for a graph/network node id.
  function entityPath(id) {
    const i = String(id).indexOf(":");
    const k = String(id).slice(0, i),
      v = String(id).slice(i + 1);
    if (k === "doc") return `/p/doc/${v}`;
    if (k === "person") return `/p/entity/person/${encodeURIComponent(v)}`;
    if (k === "pc") return `/p/entity/pc/${encodeURIComponent(v)}`;
    if (k === "host") {
      const pc = F.sel.entity && F.sel.entity("pc", v);
      return pc ? `/p/entity/pc/${encodeURIComponent(v)}` : `/p/entity/host/${encodeURIComponent(v)}`;
    }
    if (k === "email") return `/p/entity/email/${encodeURIComponent(v)}`;
    return null;
  }
  const short = (s, n) => {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  };

  // ================= link chain =================
  // chain_get → a vertical card: every step is a node, the connector between steps carries the edge label;
  // a reversed edge (the path walks it backwards) gets an up arrow.
  const CH = { res: null, from: "", idx: 0, err: "" };
  function chainCard(res, title, idx = 0, closable = true) {
    if (!res) return "";
    const chains = res.chains || [];
    if (!res.found || !chains.length)
      return `<div class="card pad ins-chain ins-chain-none">${ic("info")}<span>${esc(F.t("insights.no_path", "Путь до инфраструктуры не найден: у этого узла нет связей с ПК, серверами или доменом."))}</span>${closable ? `<button class="btn sm" data-act="ins-chain-close">${esc(F.t("common.close", "Закрыть"))}</button>` : ""}</div>`;
    const c = chains[Math.min(idx, chains.length - 1)];
    const tabs =
      chains.length > 1
        ? `<div class="seg ins-chain-tabs" role="radiogroup" aria-label="${esc(F.t("insights.paths", "Пути"))}">${chains
            .map(
              (x, i) =>
                `<button class="${i === idx ? "on" : ""}" role="radio" aria-checked="${i === idx}" data-act="ins-chain-tab:${i}">${esc(short(x.steps[x.steps.length - 1].node.label, 18))}</button>`,
            )
            .join("")}</div>`
        : "";
    const steps = c.steps
      .map((s, i) => {
        const p = entityPath(s.node.id);
        const via =
          i > 0
            ? `<div class="ins-chain-via"><span class="ins-chain-ar">${s.reverse ? "↑" : "↓"}</span><span>${esc(viaLabel(s.via))}</span></div>`
            : "";
        return `${via}<div class="ins-chain-step ${i === c.steps.length - 1 ? "last" : ""} ${p ? "tap" : ""}" ${p ? `data-act="go:${p}"` : ""}>${ui.leadIcon(kindIc(s.node.kind))}<div class="body"><div class="t">${esc(s.node.label)}</div><div class="s">${esc(kindLabel(s.node.kind))}</div></div>${p ? ic("chev", "chev") : ""}</div>`;
      })
      .join("");
    return `<div class="card ins-chain"><div class="ins-chain-h"><b>${ic("graph")}${esc(F.t("insights.chain", "Цепочка связи"))}</b><span class="muted">${esc(title || "")} · ${plural(c.hops, F.t("insights.step_one", "шаг"), F.t("insights.step_few", "шага"), F.t("insights.step_many", "шагов"))}</span>${closable ? `<button class="icon-btn ins-chain-x" data-act="ins-chain-close" aria-label="${esc(F.t("insights.close_chain", "Закрыть цепочку"))}">${ic("x")}</button>` : ""}</div>${tabs}<div class="ins-chain-l">${steps}</div></div>`;
  }
  function runChain(args, title, cb) {
    CH.err = "";
    return F.api.chain_get(args).then(
      r => {
        Object.assign(CH, { res: r, from: title, idx: 0 });
        if (cb) cb(r);
      },
      e => {
        CH.res = { found: false, chains: [] };
        CH.err = e.message || String(e);
        if (cb) cb(CH.res);
      },
    );
  }
  // Chain as a sheet (finding card, network map, document card).
  function chainSheet(args, title) {
    runChain(args, title, () => {
      const draw = sh => {
        sh.querySelector(".sh-b").innerHTML = chainCard(CH.res, title, CH.idx, false);
      };
      F.sheet({
        title: F.t("insights.chain", "Цепочка связи"),
        html: "",
        onMount: sh => {
          draw(sh);
          F.actions["ins-chain-tab"] = i => {
            CH.idx = +i;
            draw(sh);
          };
        },
      });
    });
  }

  // ================= /p/graph: layered graph =================
  const G = { layers: null, expanded: new Set(), chain: false, zoom: 1, nodes: [] };
  function resetGraph() {
    Object.assign(G, { layers: null, expanded: new Set(), chain: false, zoom: 1, nodes: [] });
    CH.res = null;
  }
  const activeLayers = () => G.layers || LAYERS.map(l => l[0]);
  // Expanded clusters: the members and their real edges come from the same view without grouping; edges to
  // members of still-collapsed clusters are redirected to the cluster node.
  function compose(base, full) {
    if (!full || !G.expanded.size) return { nodes: base.nodes, edges: base.edges };
    const groups = base.nodes.filter(n => n.members && n.members.length && !G.expanded.has(n.id));
    const byId = new Map(full.nodes.map(n => [n.id, n]));
    const nodes = base.nodes.filter(n => !G.expanded.has(n.id));
    base.nodes
      .filter(n => G.expanded.has(n.id))
      .forEach(g => (g.members || []).forEach(m => byId.has(m) && nodes.push(byId.get(m))));
    const vis = new Set(nodes.map(n => n.id));
    const mapId = id => (vis.has(id) ? id : (groups.find(g => g.members.includes(id)) || {}).id);
    const seen = new Map();
    full.edges.forEach(e => {
      const a = mapId(e.from),
        b = mapId(e.to);
      if (!a || !b || a === b) return;
      const k = a + ">" + b + ">" + e.kind;
      if (seen.has(k)) seen.get(k).weight += e.weight || 1;
      else seen.set(k, { from: a, to: b, kind: e.kind, weight: e.weight || 1 });
    });
    return { nodes, edges: [...seen.values()] };
  }
  const COLW = 160,
    NW = 136,
    NH = 44,
    GAP = 12,
    TOP = 34;
  function layout(nodes, edges) {
    const order = LAYERS.map(l => l[0]).filter(l => nodes.some(n => n.layer === l));
    const deg = new Map();
    edges.forEach(e => {
      deg.set(e.from, (deg.get(e.from) || 0) + 1);
      deg.set(e.to, (deg.get(e.to) || 0) + 1);
    });
    const pos = new Map();
    let rows = 0;
    order.forEach((l, ci) => {
      const col = nodes
        .filter(n => n.layer === l)
        .sort(
          (a, b) => (deg.get(b.id) || 0) - (deg.get(a.id) || 0) || String(a.label).localeCompare(b.label),
        );
      rows = Math.max(rows, col.length);
      col.forEach((n, ri) => pos.set(n.id, { x: 10 + ci * COLW, y: TOP + ri * (NH + GAP), n }));
    });
    return { order, pos, w: 10 + order.length * COLW, h: TOP + rows * (NH + GAP) + 10 };
  }
  function graphSvg(view, hl) {
    const { order, pos, w, h } = layout(view.nodes, view.edges);
    G.nodes = view.nodes;
    const hlE = new Set();
    if (hl) for (let i = 1; i < hl.length; i++) hlE.add(hl[i - 1] + ">" + hl[i]).add(hl[i] + ">" + hl[i - 1]);
    const hlN = new Set(hl || []);
    const crit = critNodes();
    const edges = view.edges
      .map(e => {
        const a = pos.get(e.from),
          b = pos.get(e.to);
        if (!a || !b) return "";
        const [p, q] = a.x <= b.x ? [a, b] : [b, a];
        let d;
        if (p.x === q.x) {
          const x = p.x + NW,
            y1 = p.y + NH / 2,
            y2 = q.y + NH / 2;
          d = `M${x} ${y1} C${x + 26} ${y1} ${x + 26} ${y2} ${x} ${y2}`;
        } else {
          const x1 = p.x + NW,
            y1 = p.y + NH / 2,
            x2 = q.x,
            y2 = q.y + NH / 2,
            mx = (x1 + x2) / 2;
          d = `M${x1} ${y1} C${mx} ${y1} ${mx} ${y2} ${x2} ${y2}`;
        }
        const cls = [
          "ins-e",
          e.kind === "same_lineage" ? "dash" : "",
          hlE.has(e.from + ">" + e.to) ? "hl" : "",
        ].join(" ");
        const arrow = e.kind === "derived_from" ? ` marker-end="url(#ins-arr)"` : "";
        return `<path class="${cls}" d="${d}" stroke-width="${Math.min(4, 1 + Math.log2(e.weight || 1))}"${arrow}/>`;
      })
      .join("");
    const nodes = view.nodes
      .map((n, i) => {
        const p = pos.get(n.id);
        if (!p) return "";
        const grp = n.members && n.members.length;
        const label = short(grp ? groupLabel(n) : n.label, grp ? 13 : 15);
        const cls = ["ins-n", grp ? "grp" : "", hlN.has(n.id) ? "hl" : "", crit.has(n.id) ? "crit" : ""].join(
          " ",
        );
        return `<g class="${cls}" data-act="ins-node:${i}" role="button" tabindex="0" aria-label="${esc(grp ? label : kindLabel(n.kind) + ": " + n.label)}" transform="translate(${p.x} ${p.y})"><title>${esc(n.label)}</title><rect width="${NW}" height="${NH}" rx="10"/><use href="#i-${kindIc(n.kind)}" x="8" y="13" width="18" height="18" class="ins-ni"/><text x="32" y="27">${esc(label)}</text>${grp ? `<text class="ins-plus" x="${NW - 14}" y="28">${G.expanded.has(n.id) ? "−" : "+"}</text>` : ""}</g>`;
      })
      .join("");
    const heads = order
      .map(l => {
        const L = LAYERS.find(x => x[0] === l);
        return `<text class="ins-col" x="${10 + order.indexOf(l) * COLW}" y="18">${esc(L ? L[1] : l)}</text>`;
      })
      .join("");
    const z = G.zoom;
    return `<svg class="ins-svg" width="${Math.round(w * z)}" height="${Math.round(h * z)}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(F.t("insights.graph_aria", "Граф связей по слоям"))}"><defs><marker id="ins-arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 8 4 0 8z"/></marker></defs>${heads}${edges}${nodes}</svg>`;
  }
  // Nodes of documents/hosts that have critical or high findings (highlighted in the graph).
  function critNodes() {
    const s = new Set();
    (F.db.findings || [])
      .filter(f => (f.sev === "crit" || f.sev === "high") && f.status !== "fp")
      .forEach(f => {
        const pv = f.provenance || {};
        if (pv.doc) s.add("doc:" + pv.doc);
        if (f.host) s.add("host:" + f.host);
      });
    return s;
  }
  const critFindings = () =>
    (F.db.findings || [])
      .filter(f => (f.sev === "crit" || f.sev === "high") && f.status !== "fp" && f.status !== "fixed")
      .sort((a, b) => (a.sev === b.sev ? 0 : a.sev === "crit" ? -1 : 1))
      .slice(0, 6);
  function chainPathIds() {
    if (!CH.res || !CH.res.chains || !CH.res.chains.length) return null;
    const c = CH.res.chains[Math.min(CH.idx, CH.res.chains.length - 1)];
    return c.steps.map(s => s.node.id);
  }
  F.route("/p/graph", {
    title: () => F.t("insights.graph", "Граф связей"),
    sub: () => F.t("insights.graph_sub", "Слои, кластеры и цепочки"),
    tab: "data",
    back: true,
    render: () =>
      F.withStates(
        () => {
          const layers = activeLayers();
          const base = load({ layers });
          const full = G.expanded.size ? load({ layers, min_group: 1000 }) : null;
          if (!base || (G.expanded.size && !full)) return ui.skeletonCards(2);
          const g = base.graph;
          if (base.error || !g)
            return ui.empty({
              icon: "graph",
              title: F.t("insights.graph_na", "Граф недоступен"),
              text: base.error
                ? F.t("insights.core_err", { e: base.error }, "Ядро не вернуло аналитику: {e}")
                : F.t("insights.no_graph_data", "Нет данных для графа."),
            });
          const lc = g.layer_counts || {};
          const chips = LAYERS.map(
            ([k, l, i]) =>
              `<button class="chip ins-lchip ${layers.includes(k) ? "on" : ""}" role="checkbox" aria-checked="${layers.includes(k)}" data-act="ins-layer:${k}">${ic(i)}${l}<span class="ins-lc">${lc[k] || 0}</span></button>`,
          ).join("");
          const view = compose(g, full && full.graph);
          const hl = chainPathIds();
          const crit = critFindings();
          const mode = `<div class="seg ins-mode" role="radiogroup" aria-label="${esc(F.t("insights.mode", "Режим"))}"><button class="${G.chain ? "" : "on"}" role="radio" aria-checked="${!G.chain}" data-act="ins-mode:graph">${ic("graph")}${esc(F.t("insights.graph_btn", "Граф"))}</button><button class="${G.chain ? "on" : ""}" role="radio" aria-checked="${G.chain}" data-act="ins-mode:chain">${ic("link")}${esc(F.t("insights.chain", "Цепочка связи"))}</button></div>`;
          const chainHint = G.chain
            ? `<p class="fhint">${ic("info")} ${esc(F.t("insights.chain_hint", "Нажмите на узел графа или на критичную находку. FOCA-rs покажет путь «файл → автор → ПК → сервер → домен»."))}</p>${
                crit.length
                  ? `<div class="list ins-crit">${crit
                      .map(f =>
                        ui.row({
                          lead: ui.leadIcon("alert", f.sev === "crit" ? "var(--crit)" : "var(--bad)"),
                          title: esc(f.title),
                          sub: esc(f.host || ""),
                          act: `ins-chain-f:${f.id}`,
                        }),
                      )
                      .join("")}</div>`
                  : ""
              }`
            : "";
          return `${mode}
        <div class="chips ins-layers" role="group" aria-label="${esc(F.t("insights.layers_aria", "Слои графа"))}">${chips}</div>
        ${g.hidden ? `<p class="fhint ins-hidden">${ic("filter")} ${esc(F.t("insights.hidden_by_filter", { n: plural(g.hidden, F.t("insights.node", "узел"), F.t("insights.node_few", "узла"), F.t("insights.node_many", "узлов")) }, "Скрыто фильтром: {n}"))}</p>` : ""}
        ${CH.res ? chainCard(CH.res, CH.from, CH.idx) : chainHint}
        ${
          view.nodes.length
            ? `<div class="card ins-gwrap">${graphSvg(view, hl)}</div>
        <div class="ins-gtools"><button class="btn sm" data-act="ins-zoom:-1" aria-label="${esc(F.t("insights.zoom_out", "Уменьшить"))}">${ic("zoom-out")}</button><button class="btn sm" data-act="ins-zoom:0" aria-label="${esc(F.t("insights.zoom_100", "Масштаб 100%"))}">${Math.round(G.zoom * 100)}%</button><button class="btn sm" data-act="ins-zoom:1" aria-label="${esc(F.t("insights.zoom_in", "Увеличить"))}">${ic("zoom-in")}</button>${G.expanded.size ? `<button class="btn sm" data-act="ins-collapse">${ic("minus")}${esc(F.t("insights.collapse_all", "Свернуть всё"))}</button>` : ""}</div>
        <div class="ins-legend"><span><i class="crit"></i>${esc(F.t("insights.legend_crit", "есть критичная находка"))}</span><span><i class="grp"></i>${esc(F.t("insights.legend_grp", "кластер: нажмите, чтобы раскрыть"))}</span><span><i class="dash"></i>${esc(F.t("insights.legend_line", "одна линия версий"))}</span></div>`
            : ui.empty({
                icon: "filter",
                title: F.t("insights.all_hidden", "Все слои скрыты"),
                text: F.t("insights.enable_layer", "Включите хотя бы один слой."),
              })
        }
        ${F.helpBtn ? `<div class="btnrow">${F.helpBtn("graph-chain", F.t("insights.how_graph", "Как читать граф"))}</div>` : ""}`;
        },
        { loading: "cards" },
      ),
  });
  Object.assign(F.actions, {
    "ins-layer": k => {
      const s = new Set(activeLayers());
      s.has(k) ? s.delete(k) : s.add(k);
      G.layers = LAYERS.map(l => l[0]).filter(l => s.has(l));
      G.expanded.clear();
      F.render(true);
    },
    "ins-mode": m => {
      G.chain = m === "chain";
      if (!G.chain) CH.res = null;
      F.render(true);
    },
    "ins-zoom": d => {
      G.zoom = +d === 0 ? 1 : Math.max(0.5, Math.min(2, G.zoom + +d * 0.25));
      F.render(true);
    },
    "ins-collapse": () => {
      G.expanded.clear();
      F.render(true);
    },
    "ins-chain-close": () => {
      CH.res = null;
      F.render(true);
    },
    "ins-chain-tab": i => {
      CH.idx = +i;
      F.render(true);
    },
    "ins-chain-f": id => {
      const f = (F.db.findings || []).find(x => String(x.id) === String(id));
      runChain({ from_id: +id }, f ? short(f.title, 40) : "", () => {
        G.chain = true;
        F.render(true);
      });
    },
    "ins-chain": arg => {
      // arg: "f:<finding id>" or "n:<node id>"
      const [k, v] = String(arg).split(/:(.*)/s);
      const f = k === "f" && (F.db.findings || []).find(x => String(x.id) === v);
      chainSheet(k === "f" ? { from_id: +v } : { node: v }, f ? short(f.title, 40) : v.replace(/^\w+:/, ""));
    },
    "ins-node": i => {
      const n = G.nodes[+i];
      if (!n) return;
      const grp = n.members && n.members.length;
      if (grp) {
        G.expanded.has(n.id) ? G.expanded.delete(n.id) : G.expanded.add(n.id);
        F.render(true);
        return;
      }
      if (G.chain) {
        runChain({ node: n.id }, n.label, () => F.render(true));
        return;
      }
      const p = entityPath(n.id);
      F.sheet({
        title: short(n.label, 40),
        html: `<div class="kv"><div class="kvr"><div class="k">${esc(F.t("insights.type", "Тип"))}</div><div class="v">${esc(kindLabel(n.kind))}</div></div><div class="kvr"><div class="k">${esc(F.t("insights.layer_label", "Слой"))}</div><div class="v">${esc((LAYERS.find(l => l[0] === n.layer) || [0, n.layer])[1])}</div></div></div>`,
        footer: `<button class="btn tonal" data-act="ins-chain:n:${esc(n.id)}">${ic("link")}${esc(F.t("insights.chain", "Цепочка связи"))}</button>${p ? `<button class="btn primary" data-act="go:${p}">${esc(F.t("common.open", "Открыть"))}</button>` : ""}`,
      });
    },
  });

  // ================= /p/netmap: internal network map =================
  const ROLE = tt("insights.role", {
    dc: ["Контроллер домена", "domain"],
    pki: ["PKI / УЦ", "lock"],
    ca: ["PKI / УЦ", "lock"],
    file: ["Файловый сервер", "folder"],
    mail: ["Почтовый сервер", "mail"],
    print: ["Принт-сервер", "printer"],
    web: ["Веб-сервер", "globe"],
    db: ["База данных", "db"],
    app: ["Сервер приложений", "app"],
    rdp: ["Терминальный сервер", "monitor"],
  });
  const ROLE_ORDER = ["dc", "pki", "ca", "file", "mail", "print", "web", "db", "app", "rdp"];
  const roleOf = n => ROLE_ORDER.find(r => (n.roles || []).includes(r)) || "other";
  const SRC_KIND = tt("insights.src_kind", {
    unc: "UNC-путь",
    path: "путь в документе",
    printer: "принтер",
    lnk: "ярлык LNK",
    eml: "заголовок письма",
    received: "заголовок Received",
    people: "word/people.xml",
    cdp: "сертификат: CDP",
    aia: "сертификат: AIA",
    cert: "сертификат",
    rdp: "файл RDP",
    meta: "метаданные",
  });
  const NM = { nodes: [] };
  function nmRow(n, depth) {
    NM.nodes.push(n);
    const i = NM.nodes.length - 1;
    const sub = [
      n.fqdn ? `<span class="mono">${esc(n.fqdn)}</span>` : "",
      (n.roles || []).length ? esc(n.roles.map(r => (ROLE[r] || [r])[0]).join(", ")) : "",
      n.confidence ? F.t("insights.conf_n", { n: n.confidence }, "уверенность {n}%") : "",
    ]
      .filter(Boolean)
      .join(" · ");
    return `<div class="row tap ins-nm-r d${depth}" data-act="ins-nm:${i}">${ui.leadIcon(n.kind === "server" ? (ROLE[roleOf(n)] || [0, "server"])[1] : kindIc(n.kind))}<div class="body"><div class="t">${esc(n.label)}</div>${sub ? `<div class="s">${sub}</div>` : ""}</div>${ic("chev", "chev")}</div>`;
  }
  function netmapHtml(nm) {
    NM.nodes = [];
    const nodes = nm.nodes || [];
    const kids = id => nodes.filter(n => n.parent === id);
    const roots = nodes.filter(n => !n.parent || !nodes.some(m => m.id === n.parent));
    const domainBlock = d => {
      const all = kids(d.id);
      const sub = all.filter(n => n.kind === "domain");
      const servers = all.filter(n => n.kind === "server");
      const ws = all.filter(n => n.kind === "workstation");
      const users = all.filter(n => n.kind === "user");
      const byRole = {};
      servers.forEach(s => (byRole[roleOf(s)] = byRole[roleOf(s)] || []).push(s));
      const roles = ROLE_ORDER.concat("other").filter(r => byRole[r]);
      const head =
        d.id === "domain:unknown"
          ? `<div class="ins-nm-h">${ui.leadIcon("domain")}<div class="body"><b>${esc(F.t("insights.no_domain", "Домен не установлен"))}</b><span class="s">${esc(F.t("insights.no_domain_sub", "узлы без имени AD-домена"))}</span></div></div>`
          : `<div class="ins-nm-h tap" data-act="ins-nm:${(NM.nodes.push(d), NM.nodes.length - 1)}">${ui.leadIcon(kindIc(d.kind))}<div class="body"><b>${esc(d.label)}</b><span class="s">${esc(kindLabel(d.kind))}${d.fqdn ? ` · <span class="mono">${esc(d.fqdn)}</span>` : ""}</span></div>${ic("chev", "chev")}</div>`;
      return `<div class="card ins-nm-d">${head}
        ${sub.map(domainBlock).join("")}
        ${roles
          .map(
            r =>
              `<div class="ins-nm-k">${ic((ROLE[r] || [0, "server"])[1])}${esc((ROLE[r] || [F.t("insights.servers", "Серверы")])[0])} · ${byRole[r].length}</div><div class="list">${byRole[
                r
              ]
                .map(
                  s =>
                    nmRow(s, 1) +
                    kids(s.id)
                      .map(u => nmRow(u, 2))
                      .join(""),
                )
                .join("")}</div>`,
          )
          .join("")}
        ${
          ws.length
            ? `<div class="ins-nm-k">${ic("monitor")}${esc(F.t("insights.ws_n", { n: ws.length }, "Рабочие станции · {n}"))}</div><div class="list">${ws
                .map(
                  w =>
                    nmRow(w, 1) +
                    kids(w.id)
                      .map(u => nmRow(u, 2))
                      .join(""),
                )
                .join("")}</div>`
            : ""
        }
        ${users.length ? `<div class="ins-nm-k">${ic("users")}${esc(F.t("insights.users_n", { n: users.length }, "Пользователи · {n}"))}</div><div class="list">${users.map(u => nmRow(u, 1)).join("")}</div>` : ""}
      </div>`;
    };
    const forests = roots.filter(n => n.kind === "forest");
    const domains = roots.filter(n => n.kind === "domain");
    const loose = roots.filter(n => n.kind !== "forest" && n.kind !== "domain");
    return (
      forests
        .map(
          f =>
            `<div class="ins-nm-f">${ic("domain")}<b>${esc(F.t("insights.forest", { name: f.label }, "Лес {name}"))}</b></div>${kids(
              f.id,
            )
              .filter(n => n.kind === "domain")
              .map(domainBlock)
              .join("")}`,
        )
        .join("") +
      domains.map(domainBlock).join("") +
      (loose.length
        ? `<div class="card ins-nm-d"><div class="ins-nm-h">${ui.leadIcon("domain")}<div class="body"><b>${esc(F.t("insights.no_domain", "Домен не установлен"))}</b><span class="s">${esc(F.t("insights.no_domain_sub", "узлы без имени AD-домена"))}</span></div></div><div class="list">${loose
            .map(
              n =>
                nmRow(n, 1) +
                kids(n.id)
                  .map(u => nmRow(u, 2))
                  .join(""),
            )
            .join("")}</div></div>`
        : "")
    );
  }
  F.route("/p/netmap", {
    title: () => F.t("insights.netmap", "Схема внутренней сети"),
    sub: () => F.t("insights.netmap_sub", "Из путей, принтеров, LNK, писем и сертификатов"),
    tab: "data",
    back: true,
    render: () =>
      F.withStates(
        () => {
          const r = ins();
          if (!r) return ui.skeletonCards(3);
          const nm = r.netmap || { nodes: [] };
          if (r.error || !nm.nodes.length)
            return ui.empty({
              icon: "net",
              title: F.t("insights.netmap_empty", "Схема сети пока пуста"),
              text: F.t(
                "insights.netmap_empty_text",
                "Внутренние серверы, домен и рабочие станции появятся из UNC-путей, принтеров, ярлыков LNK, заголовков писем и сертификатов (CDP/AIA).",
              ),
            });
          const cnt = k => nm.nodes.filter(n => n.kind === k).length;
          return `<div class="grid g3 ins-nm-st">
            <div class="card stat"><div class="k">${esc(F.t("insights.servers", "Серверы"))}</div><div class="v">${cnt("server")}</div><div class="d">${esc(F.t("insights.by_roles", "по ролям"))}</div></div>
            <div class="card stat"><div class="k">${esc(F.t("insights.pc", "ПК"))}</div><div class="v">${cnt("workstation")}</div><div class="d">${esc(F.t("insights.workstations", "рабочие станции"))}</div></div>
            <div class="card stat"><div class="k">${esc(F.t("insights.people", "Люди"))}</div><div class="v">${cnt("user")}</div><div class="d">${esc(F.t("insights.accounts", "учётные записи"))}</div></div>
          </div>
          <p class="fhint">${ic("info")} ${esc(F.t("insights.tree_hint", "Дерево: домен → серверы по ролям → рабочие станции → пользователи. Нажмите на узел, чтобы увидеть, из каких документов он известен."))}</p>
          ${netmapHtml(nm)}
          ${F.helpBtn ? `<div class="btnrow">${F.helpBtn("netmap", F.t("insights.about_netmap", "О схеме сети"))}</div>` : ""}`;
        },
        { loading: "cards" },
      ),
  });
  F.actions["ins-nm"] = i => {
    const n = NM.nodes[+i];
    if (!n) return;
    const src = (n.sources || [])
      .map(s =>
        ui.row({
          lead: ui.leadIcon(s.doc ? "doc" : "info"),
          title: `<span class="mono ins-src-v">${esc(s.value)}</span>`,
          sub: esc(SRC_KIND[s.kind] || s.kind) + (s.doc ? ` · ${esc(docName(s.doc))}` : ""),
          act: s.doc ? `go:/p/doc/${s.doc}` : "",
        }),
      )
      .join("");
    const extra = [
      (n.shares || []).length
        ? `<div class="kvr"><div class="k">${esc(F.t("insights.shares", "Папки"))}</div><div class="v mono">${esc(n.shares.join(", "))}</div></div>`
        : "",
      (n.printers || []).length
        ? `<div class="kvr"><div class="k">${esc(F.t("insights.printers", "Принтеры"))}</div><div class="v mono">${esc(n.printers.join(", "))}</div></div>`
        : "",
    ].join("");
    const p = entityPath(n.id);
    F.sheet({
      title: n.label || F.t("insights.node_title", "Узел"),
      html: `<div class="kv"><div class="kvr"><div class="k">${esc(F.t("insights.type", "Тип"))}</div><div class="v">${esc(kindLabel(n.kind))}</div></div>${n.confidence ? `<div class="kvr"><div class="k">${esc(F.t("insights.confidence", "Уверенность"))}</div><div class="v">${n.confidence}%</div></div>` : ""}${extra}</div>${ui.secH(F.t("insights.sources", "Источники"), (n.sources || []).length)}<div class="list">${src || `<div class="row"><div class="body"><div class="s">${esc(F.t("insights.no_sources", "Источники не указаны"))}</div></div></div>`}</div>`,
      footer: `<button class="btn tonal" data-act="ins-chain:n:${esc(n.id.replace(/^(server|workstation):/, "host:"))}">${ic("link")}${esc(F.t("insights.chain", "Цепочка связи"))}</button>${p ? `<button class="btn primary" data-act="go:${p}">${esc(F.t("common.open", "Открыть"))}</button>` : ""}`,
    });
  };
  const docName = id => {
    const d = (F.db.docs || []).find(x => x.id === +id);
    return d ? d.name : F.t("insights.doc_n", { id }, "документ {id}");
  };

  // ================= /p/timeline: year lanes and the 7×24 heat map =================
  const LANES = tt(
    "insights.lane",
    [
      ["documents", "Документы", "doc"],
      ["software", "ПО", "app"],
      ["certificates", "CT", "lock"],
    ],
    1,
  );
  // Lane headers carry a short form for narrow cards (large font on a phone), so long words are never
  // broken mid-word; the full name stays in the title and for screen readers.
  const LANE_SHORT = { documents: "Док.", software: "ПО" };
  const laneHead = (k, l, i) => {
    const short = LANE_SHORT[k] ? F.t(`insights.lane_short.${k}`, LANE_SHORT[k]) : l;
    return `<span role="columnheader" title="${esc(l)}">${ic(i)}<span class="ins-ln-l">${esc(l)}</span><span class="ins-ln-s" aria-hidden="true">${esc(short)}</span></span>`;
  };
  function lanesHtml() {
    const r = ins();
    if (!r || r.error || !(r.timeline || []).length) return "";
    const years = [...new Set(r.timeline.map(t => t.year))].sort((a, b) => b - a);
    const cell = (y, lane) => {
      const l = r.timeline.filter(t => t.year === y && t.lane === lane);
      if (!l.length) return `<span class="ins-ln-c none">-</span>`;
      const labels = [...new Set(l.map(t => t.label))];
      return `<span class="ins-ln-c"><b>${l.length}</b><small>${esc(short(labels.slice(0, 2).join(", "), 22))}${labels.length > 2 ? ` +${labels.length - 2}` : ""}</small></span>`;
    };
    return `${ui.secH(F.t("insights.evolution", "Эволюция по годам"), F.t("insights.docs_lane", "документы · ПО · CT"))}
      <div class="card ins-lanes" role="table" aria-label="${esc(F.t("insights.chrono_aria", "Хронология по годам"))}">
        <div class="ins-ln-r head" role="row"><span role="columnheader">${esc(F.t("insights.year", "Год"))}</span>${LANES.map(([k, l, i]) => laneHead(k, l, i)).join("")}</div>
        ${years
          .slice(0, 12)
          .map(
            y =>
              `<div class="ins-ln-r tap" role="row" data-act="ins-year:${y}"><span class="ins-ln-y">${y}</span>${LANES.map(([k]) => cell(y, k)).join("")}</div>`,
          )
          .join("")}
      </div>${years.length > 12 ? `<p class="fhint">${esc(F.t("insights.last12", { n: years.length }, "Показаны последние 12 лет из {n}."))}</p>` : ""}`;
  }
  F.actions["ins-year"] = y => {
    const r = ins();
    if (!r) return;
    const l = r.timeline.filter(t => t.year === +y);
    F.sheet({
      title: F.t("insights.year_n", { y }, "{y} год"),
      html: LANES.map(([k, name, i]) => {
        const xs = l.filter(t => t.lane === k);
        if (!xs.length) return "";
        const cnt = {};
        xs.forEach(t => (cnt[t.label] = (cnt[t.label] || 0) + 1));
        return `${ui.secH(name, xs.length)}<div class="chips wrap">${Object.entries(cnt)
          .sort((a, b) => b[1] - a[1])
          .map(([t, n]) => `<span class="chip">${ic(i)}${esc(t)}${n > 1 ? ` · ${n}` : ""}</span>`)
          .join("")}</div>`;
      }).join(""),
    });
  };
  const DAYS = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"];
  const day = d => F.t(`insights.day.${d}`, DAYS[d]);
  // The core's joint weekday×hour grid; working hours (weekdays, settings range) are outlined and non-empty
  // cells outside them are marked.
  function heatHtml(wh) {
    const r = ins();
    const a = r && !r.error && r.activity;
    if (!a || !a.matrix || !a.total) return null;
    const from = (wh && wh.from) ?? 8,
      to = (wh && wh.to) ?? 19;
    const max = Math.max(1, ...a.matrix.flat());
    const ooh = (d, h) => d >= 5 || h < from || h >= to;
    const pct = n => (a.total ? Math.round((n / a.total) * 100) : 0);
    const byH = a.hours || [];
    const mh = Math.max(0, ...byH);
    const hot = byH.map((v, h) => (mh && v >= mh * 0.8 ? h : -1)).filter(h => h >= 0);
    // Shares from the same grid: weekday cells inside the working hours, and Saturday/Sunday rows.
    const sumCells = f =>
      a.matrix.reduce((s, row, d) => s + row.reduce((t, v, h) => t + (f(d, h) ? v : 0), 0), 0);
    const work = sumCells((d, h) => d < 5 && h >= from && h < to);
    const weekend = sumCells(d => d >= 5);
    return `${ui.secH(F.t("insights.heatmap", "Тепловая карта активности"), "7 × 24")}
      <div class="card pad v2t-heat ins-heat">
        <div class="v2t-hg ins-hg" role="img" aria-label="${esc(F.t("insights.heatmap_aria", "Тепловая карта: дни недели по часам, рабочие часы обведены"))}">
          <span></span>${Array.from({ length: 24 }, (_, h) => `<span class="v2t-hh">${h % 6 === 0 ? h : ""}</span>`).join("")}
          ${a.matrix
            .map(
              (row, d) =>
                `<span class="v2t-hd">${day(d)}</span>${row
                  .map(
                    (v, h) =>
                      `<i class="${v && ooh(d, h) ? "ooh" : ""}" style="--v:${((v / max) * 100).toFixed(0)}%" title="${day(d)} ${h}:00 · ${v}"></i>`,
                  )
                  .join("")}`,
            )
            .join("")}
          <b class="ins-wk" style="grid-row:2 / 7;grid-column:${from + 2} / ${to + 2}" aria-hidden="true"></b>
        </div>
        <div class="v2t-hl"><span><i class="ins-wk-l"></i>${esc(F.t("insights.wh_legend", { from, to }, "рабочие часы {from}-{to}, Пн-Пт"))} · <i class="ins-ooh-l"></i>${esc(F.t("insights.ooh", "вне графика"))}</span></div>
        <div class="v2t-out">
          <div>${ic("clock")}<span><b>${esc(F.t("insights.peak", { v: hot.length ? F.t("insights.hours_range", { a: hot[0], b: hot[hot.length - 1] + 1 }, "{a}-{b} ч") : "-" }, "Пик: {v}"))}</b>${a.tz ? ` · ${esc(F.t("insights.doc_tz", { tz: a.tz }, "часовой пояс документов {tz}"))}` : ""}</span></div>
          <div>${ic("v2-cal")}<span><b>${esc(F.t("insights.wh_t", { from, to }, "Рабочие часы {from}-{to}"))}</b> ${esc(F.t("insights.wh_d", { p: pct(work) }, "в будни: {p}% документов"))}</span></div>
          <div>${ic("v2-cal")}<span>${esc(F.t("insights.weekend", { p: pct(weekend) }, "Выходные: {p}% активности"))}</span></div>
          <div>${ic("moon")}<span><b>${esc(F.t("insights.ooh_t", { p: pct(a.out_of_hours || 0) }, "Вне графика: {p}%"))}</b> (${esc(F.t("insights.ooh_d", { n: plural(a.out_of_hours || 0, F.t("insights.doc_word", "документ"), F.t("insights.doc_few", "документа"), F.t("insights.doc_many", "документов")) }, "{n}: вечер, ночь, выходные"))})</span></div>
        </div>
      </div>`;
  }

  // ================= org chart =================
  const DEPT = tt("insights.dept", {
    finance: "Финансы и бухгалтерия",
    hr: "Кадры",
    legal: "Юридический отдел",
    it: "ИТ",
    sales: "Продажи",
    marketing: "Маркетинг",
    management: "Руководство",
    procurement: "Закупки",
    logistics: "Логистика",
    security: "Безопасность",
    production: "Производство",
    engineering: "Инженерный отдел",
    planning: "Планирование",
    quality: "Качество",
  });
  const deptLabel = d => DEPT[d.key] || (d.labels || [])[0] || d.key || F.t("insights.dept", "Отдел");
  const EVID = tt("insights.evid", {
    local_path: "локальный путь",
    unc: "сетевая папка",
    share: "сетевая папка",
    printer: "принтер",
    ou: "OU сертификата",
    company: "поле «Организация»",
    department: "поле «Отдел»",
    role: "роль в документе",
    title: "должность из сертификата",
    email: "адрес e-mail",
  });
  const personName = l => {
    const p = (F.db.people || []).find(x => x.login === l);
    return p ? p.name : l;
  };
  const ORG = { members: [] };
  function orgHtml(limit) {
    const r = ins();
    const deps = (r && !r.error && r.org && r.org.departments) || [];
    if (!deps.length) return "";
    ORG.members = [];
    const chip = (d, m, maybe) => {
      ORG.members.push({ d, m });
      return `<button class="chip ins-org-m ${maybe ? "maybe" : ""}" data-act="ins-org:${ORG.members.length - 1}">${ic("user")}${esc(short(personName(m.login), 22))}<small>${m.confidence}%</small></button>`;
    };
    const list = deps.slice(0, limit || deps.length);
    return `${ui.secH(F.t("insights.org", "Оргструктура"), plural(deps.length, F.t("insights.dept_one", "отдел"), F.t("insights.dept_few", "отдела"), F.t("insights.dept_many", "отделов")), F.helpBtn ? F.helpBtn("org-chart", F.t("common.details", "Подробнее")) : "")}
      <div class="ins-org">${list
        .map(
          d =>
            `<div class="card pad ins-org-d"><div class="ins-org-h"><b>${esc(deptLabel(d))}</b><span class="pill mute">${esc(F.t("insights.conf_n", { n: d.confidence }, "уверенность {n}%"))}</span></div><div class="chips wrap">${d.members.map(m => chip(d, m)).join("")}</div>${
              (d.candidates || []).length
                ? `<details class="ins-org-c"><summary>${esc(F.t("insights.maybe_more", { n: d.candidates.length }, "Возможно, ещё {n}"))}</summary><div class="chips wrap">${d.candidates.map(m => chip(d, m, true)).join("")}</div></details>`
                : ""
            }</div>`,
        )
        .join(
          "",
        )}</div>${limit && deps.length > limit ? `<div class="btnrow"><button class="btn sm tonal" data-act="go:/p/data/people">${esc(F.t("insights.all_depts", { n: deps.length }, "Все отделы ({n})"))}</button></div>` : ""}`;
  }
  F.actions["ins-org"] = i => {
    const x = ORG.members[+i];
    if (!x) return;
    const { d, m } = x;
    F.sheet({
      title: personName(m.login),
      html: `<p class="lead">${esc(deptLabel(d))} · ${esc(F.t("insights.conf_n", { n: m.confidence }, "уверенность {n}%"))}.</p>${ui.secH(F.t("insights.rationale", "Обоснование"), (m.evidence || []).length)}<div class="list">${(
        m.evidence || []
      )
        .map(e =>
          ui.row({
            lead: ui.leadIcon(e.doc ? "doc" : "info"),
            title: `<span class="mono ins-src-v">${esc(e.value)}</span>`,
            sub: `${esc(EVID[e.source] || e.source)}${e.weight ? ` · ${F.t("insights.weight", { n: e.weight }, "вес {n}")}` : ""}${e.doc ? ` · ${esc(docName(e.doc))}` : ""}`,
            act: e.doc ? `go:/p/doc/${e.doc}` : "",
          }),
        )
        .join(
          "",
        )}</div><p class="fhint">${ic("info")} ${esc(F.t("insights.dept_note", "Отдел выводится из путей, папок, принтеров и полей документов. Это гипотеза аналитика, не факт."))}</p>`,
      footer: `<button class="btn primary" data-act="go:/p/entity/person/${encodeURIComponent(m.login)}">${esc(F.t("insights.person_card", "Карточка человека"))}</button>`,
    });
  };
  function renderAttackPaths() {
    const r = loadAttackPaths();
    if (!r) return ui.skeletonCards(3);
    if (r.error) return ui.error({ text: r.error });
    const paths = r.paths || [];
    const chokes = r.choke_points || [];
    const sum = r.summary || {};
    if (!paths.length && !chokes.length) {
      return ui.empty({
        icon: "shield",
        title: F.t("insights.attack_paths", "Пути компрометации"),
        text: F.t("insights.no_paths", "Многошаговых цепочек компрометации пока не выявлено."),
      });
    }
    const apSev = s => ui.sev(s === "medium" ? "warn" : s === "critical" ? "crit" : s || "info");
    // Node kinds and likelihood are engine codes: shown in the UI language.
    const KIND = {
      document: F.t("insights.ap_kind_document", "документ"),
      credential: F.t("insights.ap_kind_credential", "учётные данные"),
      exposure: F.t("insights.ap_kind_exposure", "раскрытие данных"),
      identity: F.t("insights.ap_kind_identity", "учётная запись"),
      perimeter: F.t("insights.ap_kind_perimeter", "периметр"),
      vulnerability: F.t("insights.ap_kind_vulnerability", "уязвимость"),
    };
    const LIKE = {
      high: F.t("insights.ap_like_high", "вероятность высокая"),
      medium: F.t("insights.ap_like_medium", "вероятность средняя"),
      low: F.t("insights.ap_like_low", "вероятность низкая"),
    };
    // Titles of linked findings: a finding replaced by a later analysis still shows its title.
    F.findingTitles = F.findingTitles || {};
    for (const p of paths)
      for (const st of p.steps || [])
        if (st.finding_id && st.kind !== "document" && st.kind !== "perimeter")
          F.findingTitles[st.finding_id] = st.kind === "vulnerability" ? st.detail : st.label;
    return `
      <div class="card pad ins-ap-sum">
        <div class="ins-ap-stats">
          <div><b>${sum.total_paths || paths.length}</b><small>${esc(F.t("insights.paths_l", "цепочек"))}</small></div>
          <div><b>${sum.critical_or_high || 0}</b><small>${esc(F.t("insights.crit_high", "крит./выс."))}</small></div>
          <div><b>${sum.choke_points || chokes.length}</b><small>${esc(F.t("insights.choke_l", "точек блок."))}</small></div>
          <div><b>${sum.max_score || 0}</b><small>${esc(F.t("insights.max_score", "макс. балл"))}</small></div>
        </div>
        ${F.helpBtn ? F.helpBtn("attack-paths", F.t("insights.attack_paths", "Пути компрометации")) : ""}
      </div>
      ${
        chokes.length
          ? `${ui.secH(F.t("insights.choke_points", "Ключевые точки блокировки"), chokes.length)}
            <div class="list ins-ap-chokes">${chokes
              .map(cp => {
                const act =
                  cp.finding_ids && cp.finding_ids.length
                    ? `go:/p/finding/${cp.finding_ids[0]}`
                    : entityPath(cp.node_id)
                      ? `go:${entityPath(cp.node_id)}`
                      : "";
                return `<div class="card pad ins-ap-cp ${act ? "tap" : ""}" ${act ? `data-act="${esc(act)}"` : ""}>
                  <div class="ins-ap-cph">
                    <b>${esc(ftx(cp.label, ""))}</b>
                    <span class="pill warn">${esc(F.t("insights.breaks", { n: cp.paths_broken || 0 }, "разрывает {n}"))}</span>
                    <span class="pill mute">${cp.priority_score || 0}/100</span>
                  </div>
                  <p class="ins-ap-rec">${esc(ftx(cp.recommendation, ""))}</p>
                </div>`;
              })
              .join("")}</div>`
          : ""
      }
      ${ui.secH(F.t("insights.attack_paths", "Пути компрометации"), paths.length)}
      <div class="ins-ap-list">${paths
        .map(
          p => `<div class="card pad ins-ap-card">
            <div class="ins-ap-hd">
              ${apSev(p.severity)}
              <span class="pill mute">${p.score || 0}/100 · ${esc(LIKE[p.likelihood] || p.likelihood || "")}</span>
              ${p.target_host ? `<span class="chip mono">${esc(p.target_host)}</span>` : ""}
            </div>
            <h4 class="ins-ap-t">${esc(apTitle(p.title))}</h4>
            <div class="ins-ap-steps">${(p.steps || [])
              .map((st, idx) => {
                const link = st.doc_id
                  ? `go:/p/doc/${st.doc_id}`
                  : st.finding_id
                    ? `go:/p/finding/${st.finding_id}`
                    : entityPath(st.node_id)
                      ? `go:${entityPath(st.node_id)}`
                      : "";
                return `${idx > 0 ? `<div class="ins-ap-ar">↓</div>` : ""}<div class="ins-ap-st ${link ? "tap" : ""}" ${link ? `data-act="${esc(link)}"` : ""}>
                  <span class="pill mute">${esc(KIND[st.kind] || st.kind)}</span>
                  <div class="body"><div class="t">${esc(ftx(st.label, ""))}</div>${st.detail ? `<div class="s">${esc(ftx(st.detail, ""))}</div>` : ""}</div>
                  ${link ? ic("chev", "chev") : ""}
                </div>`;
              })
              .join("")}</div>
          </div>`,
        )
        .join("")}</div>`;
  }
  F.route("/p/attack-paths", {
    title: () => F.t("insights.attack_paths", "Пути компрометации"),
    sub: () => (F.project && F.project.name) || "",
    nav: false,
    back: true,
    actions: () => F.defaultActions,
    render: () => F.withStates(renderAttackPaths, { loading: "cards" }),
  });

  function overviewHtml() {
    const r = ins();
    if (!r || r.error) return "";
    const c = r.counts || {};
    const apSum = (r.attack_paths && r.attack_paths.summary) || (AP_CACHE.get(pid()) || {}).summary || {};
    const apTotal = apSum.total_paths ?? c.attack_paths;
    const links = [
      [
        "graph",
        F.t("insights.graph", "Граф связей"),
        F.tp(
          "insights.nodes_n",
          c.graph_nodes || 0,
          { n: c.graph_nodes || 0 },
          "{n} узел|{n} узла|{n} узлов",
        ),
        "/p/graph",
      ],
      [
        "shield",
        F.t("insights.attack_paths", "Пути компрометации"),
        apTotal != null
          ? F.t(
              "insights.ap_sum",
              { n: apTotal, k: apSum.choke_points || 0 },
              "цепочки: {n} · узловые точки: {k}",
            )
          : F.t("insights.chains_points", "цепочки и точки"),
        "/p/attack-paths",
      ],
      [
        "net",
        F.t("insights.netmap_short", "Схема сети"),
        F.tp("insights.nodes_n", c.net_nodes || 0, { n: c.net_nodes || 0 }, "{n} узел|{n} узла|{n} узлов"),
        "/p/netmap",
      ],
      [
        "users",
        F.t("insights.org", "Оргструктура"),
        plural(
          c.departments || 0,
          F.t("insights.dept_one", "отдел"),
          F.t("insights.dept_few", "отдела"),
          F.t("insights.dept_many", "отделов"),
        ),
        "/p/data/people",
      ],
      [
        "history",
        F.t("insights.timeline", "Хронология"),
        F.t("insights.by_years", "по годам и часам"),
        "/p/timeline",
      ],
    ];
    return `${ui.secH(F.t("insights.picture", "Картина инфраструктуры"))}
      <div class="grid g2 ins-ov">${links
        .map(
          ([i, l, s, p]) =>
            `<div class="card tap qlink" data-act="go:${p}"><div class="qlink-in">${ui.leadIcon(i)}<span>${l}<small class="ins-ov-s">${esc(s)}</small></span></div></div>`,
        )
        .join("")}</div>`;
  }

  // ================= findings and documents =================
  const ANOM = tt("insights.anom", {
    created_after_modified:
      "Дата создания позже даты изменения. Даты правили или файл пересохраняли с другим часовым поясом.",
    future_date: "Дата из будущего относительно сканирования. Часы ПК сбиты или дату подделали.",
    date_mismatch: "Даты в разных полях (PDF/XMP/EXIF) расходятся.",
    history_after_modified: "История правок XMP заканчивается позже даты изменения.",
    history_before_created:
      "История правок XMP начинается раньше даты создания. Файл унаследован от старого документа.",
    history_agent_mismatch: "Программа в истории XMP не совпадает с полем «Producer».",
    software_newer_than_document: "Версия программы вышла позже даты документа.",
    edit_time_exceeds_lifetime: "Время правки больше, чем прошло между созданием и изменением.",
    comment_before_created: "Комментарий датирован раньше создания документа.",
  });
  // Built at render time: the dictionary may arrive after the script ran and the language can change.
  const KEV_NOTE = () =>
    `<div class="banner info ins-kev">${ic("info")}<div><b>${esc(F.t("insights.kev_t", "Проверьте версию."))}</b> ${esc(F.t("insights.kev_d", "CISA KEV: каталог уязвимостей, которые реально эксплуатируются. Каталог не указывает уязвимые версии: «возможно» значит, что продукт есть в каталоге; «вероятно»: версия без поддержки, а CVE опубликованы после окончания поддержки. Это повод сверить версию с бюллетенем производителя, а не подтверждённая уязвимость."))}</div></div>`;
  const kevPill = f =>
    (f.tags || []).includes("likely")
      ? `<span class="pill bad">${esc(F.t("insights.kev_likely", "KEV · вероятно"))}</span>`
      : `<span class="pill warn">${esc(F.t("insights.kev_possible", "KEV · возможно"))}</span>`;
  function findingBlock(f) {
    if (!f) return "";
    const rule = (f.provenance && f.provenance.rule) || "";
    const out = [];
    if (rule === "sw.kev") {
      out.push(KEV_NOTE());
      if ((f.cve || []).length)
        out.push(
          `<div class="chips wrap ins-cves">${kevPill(f)}${f.cve
            .slice(0, 12)
            .map(
              c => `<span class="chip mono">${esc(typeof c === "string" ? c : c.id || c.cve || "")}</span>`,
            )
            .join("")}</div>`,
        );
    }
    if (rule === "doc.lineage")
      out.push(
        `<p class="fhint">${ic("doc")}<span>${esc(F.t("insights.lineage_note", "Копии и версии одного документа (общие идентификаторы XMP/RSID). Список: в карточке документа, раздел «Версии и копии»."))}</span></p>`,
      );
    if (rule === "net.internal_map")
      out.push(
        `<div class="btnrow"><button class="btn sm tonal" data-act="go:/p/netmap">${ic("net")}${esc(F.t("insights.netmap", "Схема внутренней сети"))}</button></div>`,
      );
    if (rule === "org.structure")
      out.push(
        `<div class="btnrow"><button class="btn sm tonal" data-act="go:/p/data/people">${ic("users")}${esc(F.t("insights.org", "Оргструктура"))}</button></div>`,
      );
    if (/^recon\.web\./.test(rule)) out.push(webAuditMini(f.host));
    const rel = f.rel || {};
    const chainable =
      (f.provenance && f.provenance.doc) || (rel.pcs || []).length || (rel.people || []).length || f.host;
    if (chainable && (f.sev === "crit" || f.sev === "high" || /^doc\./.test(rule)))
      out.push(
        `<div class="btnrow"><button class="btn sm tonal" data-act="ins-chain:f:${f.id}">${ic("link")}${esc(F.t("insights.chain", "Цепочка связи"))}</button></div>`,
      );
    return out.join("");
  }
  function docBlocks(doc) {
    const r = ins();
    if (!doc || !r || r.error) return "";
    const out = [];
    const an = (r.anomalies || []).filter(a => a.doc === doc.id);
    if (an.length)
      out.push(
        `${ui.secH(F.t("insights.anomalies", "Аномалии метаданных"), an.length, F.helpBtn ? F.helpBtn("anomalies", F.t("common.details", "Подробнее")) : "")}<div class="list">${an
          .map(a =>
            ui.row({
              lead: ui.leadIcon("alert", "var(--warn)"),
              title: esc(ftx(a.title, `doc.anomaly.${a.code}`)),
              sub: `${esc(ftx(a.detail, `doc.anomaly.${a.code}`))} · ${esc(F.t("insights.conf_n", { n: a.confidence }, "уверенность {n}%"))}`,
              cls: "ins-dr",
            }),
          )
          .join("")}</div>`,
      );
    const corr = r.correlation || {};
    const links = (corr.links || []).filter(l => l.from === doc.id || l.to === doc.id);
    if (links.length) {
      const KIND_L = {
        copy: F.t("insights.k_copy", "Копия"),
        derived_from: F.t("insights.k_derived", "Создан из"),
        same_lineage: F.t("insights.k_lineage", "Одна линия версий"),
      };
      const lin = (corr.lineages || []).find(l => (l.docs || []).includes(doc.id));
      out.push(
        `${ui.secH(F.t("insights.versions", "Версии и копии"), links.length)}<div class="list">${links
          .map(l => {
            const other = l.from === doc.id ? l.to : l.from;
            const k =
              l.kind === "derived_from" && l.to === doc.id
                ? F.t("insights.source_for", "Исходник для")
                : KIND_L[l.kind] || l.kind;
            return ui.row({
              lead: ui.leadIcon("doc"),
              cls: "ins-dr",
              title: esc(docName(other)),
              sub: `${esc(k)} · ${esc(l.basis && l.reason ? F.t(`insights.basis_${l.basis}`, l.reason) : l.reason || "")} · ${esc(F.t("insights.conf_n", { n: l.confidence }, "уверенность {n}%"))}`,
              act: `go:/p/doc/${other}`,
            });
          })
          .join(
            "",
          )}</div>${lin && lin.root ? `<p class="fhint ins-lin">${ic("info")}<span>${esc(F.t("insights.lin_root", { name: docName(lin.root) }, "Вероятный оригинал линии: {name}."))}</span></p>` : ""}`,
      );
    }
    const cl = (r.clusters || []).filter(c => (c.docs || []).includes(doc.id));
    if (cl.length) {
      const CL_KIND = {
        template: F.t("insights.cl_template", "Общий шаблон"),
        build_folder: F.t("insights.cl_build_folder", "Общая папка сборки"),
        printer_author: F.t("insights.cl_printer_author", "Тот же принтер и автор"),
        camera_serial: F.t("insights.cl_camera_serial", "Та же камера"),
      };
      out.push(
        `${ui.secH(F.t("insights.clusters", "Тот же автор или компьютер"), cl.length)}<div class="list">${cl
          .map(c => {
            const others = c.docs.filter(d => d !== doc.id);
            return ui.row({
              lead: ui.leadIcon("link"),
              cls: "ins-dr",
              title: esc(CL_KIND[c.kind] || c.kind),
              sub: `${esc(c.value)} · ${esc(others.slice(0, 5).map(docName).join(", "))}${others.length > 5 ? ` +${others.length - 5}` : ""}`,
              act: others.length ? `go:/p/doc/${others[0]}` : "",
            });
          })
          .join("")}</div>`,
      );
    }
    const sw = doc.software && (r.kev || []).find(k => k.subject && k.subject.id === doc.software);
    if (sw)
      out.push(
        `${ui.secH(F.t("insights.kev_title", "Программа в каталоге KEV"))}<div class="card pad ins-kev-d"><div class="chips wrap">${sw.confidence === "likely" ? `<span class="pill bad">${esc(F.t("insights.likely", "вероятно"))}</span>` : `<span class="pill warn">${esc(F.t("insights.possible", "возможно"))}</span>`}<span class="chip">${esc(sw.product_label)}</span><span class="chip">CVE: ${sw.total}</span></div><p class="fhint">${esc(ftx(sw.reason, "sw.kev") || F.t("insights.check_bulletin", "Сверьте версию с бюллетенем производителя."))}</p>${F.helpBtn ? F.helpBtn("kev", F.t("insights.kev_help", "Что значит «возможно/вероятно»")) : ""}</div>`,
      );
    return out.join("");
  }
  const kevOf = swId => {
    const r = ins();
    return (r && !r.error && (r.kev || []).find(k => k.subject && k.subject.id === swId)) || null;
  };

  // ================= web audit (snapshot recon.web[]) =================
  const webOf = host => {
    const rc = (F.db.raw && F.db.raw.recon) || {};
    return (rc.web || []).find(w => w.host === host) || null;
  };
  const SEV_ORDER = { crit: 0, high: 1, warn: 2, medium: 2, low: 3, info: 4 };
  const sevPill = s => ui.sev(s === "medium" ? "warn" : s);
  function webAuditMini(host) {
    if (!host || !webOf(host)) return "";
    return `<div class="btnrow"><button class="btn sm tonal" data-act="go:/p/entity/host/${encodeURIComponent(host)}">${ic("shield")}${esc(F.t("insights.webaudit_host", "Веб-аудит хоста"))}</button></div>`;
  }
  const LEVEL = tt("insights.level", {
    passive: "пассивный (без запросов)",
    standard: "стандартный (GET)",
    active: "активный",
  });

  function webAuditHost(host) {
    const w = webOf(host);
    if (!w) return "";
    const issues = (w.headers || [])
      .flatMap(h => h.issues || [])
      .sort((a, b) => (SEV_ORDER[a.sev] ?? 5) - (SEV_ORDER[b.sev] ?? 5));
    const csp = w.csp_domains || [];
    const maps = w.source_maps || [];
    const api = w.api_docs || [];
    const methods = Array.isArray(w.methods) ? w.methods : [];
    const cors = Array.isArray(w.cors) ? w.cors : [];
    const row = (t, s, sev) =>
      `<div class="row ins-wa-r"><div class="body">${sev ? `<div class="ins-wa-sev">${sevPill(sev)}</div>` : ""}<div class="t">${t}</div>${s ? `<div class="s">${s}</div>` : ""}</div></div>`;
    return `${ui.secH(F.t("insights.webaudit", "Веб-аудит"), LEVEL[w.level] || w.level || "", F.helpBtn ? F.helpBtn("webaudit", F.t("common.details", "Подробнее")) : "")}
      <div class="card pad ins-wa-s"><span>${ic("shield")}${esc(F.t("insights.wa_issues", "Проблем в заголовках:"))} <b>${issues.length}</b></span><span>${ic("globe")}${esc(F.t("insights.wa_csp", "Доменов в CSP:"))} <b>${csp.length}</b></span><span>${ic("st-code")}Source maps: <b>${maps.length}</b></span><span>${ic("plug")}${esc(F.t("insights.wa_api", "API-доки:"))} <b>${api.length}</b></span><span class="muted">${esc(F.t("insights.wa_req", { n: w.requests || 0 }, "запросов к сайту: {n}"))}</span></div>
      ${
        issues.length
          ? `<div class="list ins-wa-l">${issues
              .slice(0, 12)
              .map(i =>
                row(esc(ftx(i.title, "recon.web.issue")), esc(ftx(i.detail || "", "recon.web.issue")), i.sev),
              )
              .join("")}</div>`
          : ""
      }
      ${csp.length ? `<div class="ins-nm-k">${ic("globe")}${esc(F.t("insights.csp_domains", "Домены из CSP"))}</div><div class="chips wrap">${csp.map(d => `<span class="chip mono ${d.in_scope ? "" : "ins-oos"}">${esc(d.host)}${d.in_scope ? "" : F.t("insights.oos", " · вне скоупа")}</span>`).join("")}</div>` : ""}
      ${maps.length ? `<div class="ins-nm-k">${ic("st-code")}Source maps</div><div class="list">${maps.map(m => row(`<span class="mono ins-src-v">${esc(m.map_url || m.url || "")}</span>`, `${F.tp("insights.sources_n", m.sources_total || (m.sources || []).length || 0, { n: m.sources_total || (m.sources || []).length || 0 }, "{n} исходник|{n} исходника|{n} исходников")}${m.has_content ? F.t("insights.with_code", " · с кодом") : ""}${(m.local_paths || []).length ? ` · ${F.t("insights.local_paths", { n: m.local_paths.length }, "локальные пути: {n}")}` : ""}${(m.secrets || []).length ? ` · ${F.t("insights.secrets_n", { n: m.secrets.length }, "секреты: {n}")}` : ""}`)).join("")}</div>` : ""}
      ${api.length ? `<div class="ins-nm-k">${ic("plug")}${esc(F.t("insights.api_docs", "API-документация"))}</div><div class="list">${api.map(a => row(`${esc(a.kind)} · <span class="mono ins-src-v">${esc(a.url)}</span>`, `${a.title ? esc(a.title) + " · " : ""}${F.tp("insights.ops_n", a.operations || a.endpoints || 0, { n: a.operations || a.endpoints || 0 }, "{n} операция|{n} операции|{n} операций")}${a.unauthenticated ? ` · ${F.t("insights.unauth", { n: a.unauthenticated }, "без авторизации: {n}")}` : ""}`)).join("")}</div>` : ""}
      ${cors.length || methods.length ? `<div class="ins-nm-k">${ic("lock")}${esc(F.t("insights.cors_methods", "CORS и методы"))}</div><div class="chips wrap">${cors.map(c => `<span class="chip">${esc(typeof c === "string" ? c : `CORS: ${c.allow_origin || "-"}${c.allow_credentials ? " + credentials" : ""}${c.reflected ? F.t("insights.reflects_origin", " (отражает Origin)") : ""}`)}</span>`).join("")}${methods.map(m => `<span class="chip mono">${esc(typeof m === "string" ? m : (m.allow || []).join(", ") + (m.trace_reflected ? F.t("insights.trace_reflects", " · TRACE отражает запрос") : "") + (m.webdav ? " · WebDAV" : ""))}</span>`).join("")}</div>` : ""}`;
  }

  // One-line notes and help articles of the finding codes for the finding card (findings.js codeNote).
  if (F.fx && F.fx.CODE) {
    const WEB = tt("insights.web", {
      hsts_missing: "Сайт не отдаёт HSTS: браузер может открыть его по HTTP.",
      hsts_disabled: "HSTS выключен (max-age=0).",
      hsts_short: "Срок HSTS слишком короткий.",
      hsts_invalid: "Заголовок HSTS записан с ошибкой и игнорируется браузером.",
      hsts_preload_invalid: "Флаг preload указан без условий списка предзагрузки.",
      cors_wildcard_credentials: "CORS разрешает любой Origin вместе с cookie.",
      cors_null_origin: "CORS доверяет Origin: null (песочницы, файлы).",
      cors_wildcard: "CORS разрешает любой сайт (без cookie).",
      cors_reflected: "Сервер отражает присланный Origin в CORS.",
      cookie_flags: "У сессионного cookie нет HttpOnly, Secure или SameSite.",
      version_disclosure: "Заголовки раскрывают версии сервера и платформы.",
      clickjacking: "Нет защиты от встраивания во фрейм (кликджекинг).",
      xfo_allow_from: "X-Frame-Options: ALLOW-FROM не поддерживается браузерами.",
      xfo_invalid: "X-Frame-Options записан с ошибкой.",
      nosniff_missing: "Нет X-Content-Type-Options: nosniff.",
      referrer_policy_missing: "Нет Referrer-Policy.",
      referrer_policy_unsafe: "Referrer-Policy отдаёт полный адрес сторонним сайтам.",
      permissions_policy_missing: "Нет Permissions-Policy.",
      csp_missing: "Нет политики CSP.",
      csp_unsafe_inline: "CSP разрешает встроенные скрипты ('unsafe-inline'). Не защищает от XSS.",
      csp_unsafe_eval: "CSP разрешает eval().",
      csp_wildcard_source: "CSP разрешает скрипты с любого хоста (*).",
      csp_scheme_source: "CSP разрешает целую схему (https:, data:).",
      csp_no_script_policy: "В CSP нет правил для скриптов.",
      csp_missing_object_src: "В CSP нет object-src.",
      csp_missing_base_uri: "В CSP нет base-uri.",
      csp_report_only: "CSP только в режиме отчётов и ничего не блокирует.",
      csp_domains: "Домены из CSP выдают API, CDN и тестовые хосты.",
      sourcemap: "Открыта карта исходников JavaScript: исходный код, пути разработчиков.",
      sourcemap_secret: "В карте исходников найден секрет.",
      apidoc_openapi: "Открыта документация API (OpenAPI/Swagger).",
      apidoc_swagger_ui: "Открыт Swagger UI.",
      apidoc_graphql: "GraphQL отвечает на интроспекцию. Схема API видна целиком.",
      apidoc_actuator: "Открыт Spring Boot Actuator.",
      apidoc_openid_configuration: "Опубликована конфигурация OpenID Connect.",
      methods_unsafe_allowed: "Сервер объявляет PUT/DELETE в Allow.",
      trace_enabled: "Включён метод TRACE.",
      webdav: "Включён WebDAV.",
    });
    // Notes are getters, so they follow the current UI language.
    const note = (code, get) =>
      Object.defineProperty(F.fx.CODE, code, { get, enumerable: true, configurable: true });
    Object.keys(WEB).forEach(k => {
      note("recon.web." + k, () => F.t("insights.web_note", { v: WEB[k] }, "Веб-аудит: {v}"));
      F.fx.CODE_HELP["recon.web." + k] = "webaudit";
    });
    Object.keys(ANOM).forEach(k => {
      note("doc.anomaly." + k, () =>
        F.t(
          "insights.anom_note",
          { v: ANOM[k] },
          "Аномалия метаданных: {v} Это сигнал для аналитика, а не уязвимость.",
        ),
      );
      F.fx.CODE_HELP["doc.anomaly." + k] = "anomalies";
    });
    const CODES = tt("insights.code", {
      "sw.kev": "Продукт есть в каталоге эксплуатируемых уязвимостей CISA KEV, сверьте версию.",
      "sw.cve": "Известные CVE версии продукта из офлайн-базы NVD.",
      "doc.lineage": "Копии и версии одного документа связаны идентификаторами XMP/RSID.",
      "org.structure": "Отделы и роли восстановлены по путям, принтерам и полям документов.",
      "net.internal_map": "Внутренняя сеть (домен, серверы, ПК) восстановлена по документам.",
    });
    Object.keys(CODES).forEach(k => note(k, () => CODES[k]));
    Object.assign(F.fx.CODE_HELP, {
      "sw.kev": "kev",
      "sw.cve": "cve",
      "doc.lineage": "graph-chain",
      "org.structure": "org-chart",
      "net.internal_map": "netmap",
    });
  }

  F.ins = {
    load,
    lanesHtml,
    heatHtml,
    orgHtml,
    overviewHtml,
    findingBlock,
    docBlocks,
    kevOf,
    webAuditHost,
    chainSheet,
    netmapHtml,
  };
})();
