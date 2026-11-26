// Secondary screens (CSS prefix .v2-).
// Routes: /p/graph/:type/:id, /p/map, /p/timeline, /p/monitor, /p/diff,
// /settings/plugins, /settings/plugin/:id, /settings/ai, /p/ai, /welcome
(function () {
  const F = window.FOCA,
    { ic, esc, ui } = F;
  const demo = window.DEMO;
  const state = (F.state.v2 = F.state.v2 || {});
  const fmt = n => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, "\u00a0");
  const plural = (n, one, few, many) => {
    const a = n % 10,
      b = n % 100;
    return `${fmt(n)} ${a === 1 && b !== 11 ? one : a >= 2 && a <= 4 && (b < 12 || b > 14) ? few : many}`;
  };
  const trunc = (s, n) => (s.length > n ? s.slice(0, n - 1).trimEnd() + "…" : s);
  const hash = s => {
    let h = 7;
    for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return h;
  };

  F.addIcons(`
<symbol id="i-v2-fit"
  viewBox="0 0 16 16"><path d="M2.5 6V2.5H6M10 2.5h3.5V6M13.5 10v3.5H10M6 13.5H2.5V10"/></symbol>
<symbol id="i-v2-cal" viewBox="0 0 16 16"><rect x="2.5" y="3.5" width="11" height="10"
  rx="1.5"/><path d="M2.5 6.5h11M5.5 2v3M10.5 2v3"/></symbol>
<symbol id="i-v2-bell"
  viewBox="0 0 16 16"><path d="M4 11.5V7a4 4 0 0 1 8 0v4.5l1 1H3zM6.5 13.5a1.5 1.5 0 0 0 3 0"/></symbol>
<symbol id="i-v2-diff" viewBox="0 0 16 16"><path d="M4.5 2.5v11M2 5h5M11.5 2.5v11M9 11h5"/></symbol>
<symbol id="i-v2-send" viewBox="0 0 16 16"><path d="M2.5 8 13.5 2.5 11 13.5 7.5 9.5zM7.5 9.5l6-7"/></symbol>
<symbol id="i-v2-file"
  viewBox="0 0 16 16"><path d="M4 1.5h5.5L12.5 4.5V14.5H4zM9.5 1.5v3h3M6 8.5h4.5M6 11h4.5"/></symbol>
<symbol id="i-v2-tg"
  viewBox="0 0 16 16"><path d="M14 2.5 1.8 7.3l3.9 1.4 1.5 4.6 2.2-2.6 3.3 2.4zM5.7 8.7l6-4.4-4.5 5.4"/></symbol>
<symbol id="i-v2-hook" viewBox="0 0 16 16"><circle cx="4.5" cy="11.5" r="2"/><circle cx="11.5" cy="11.5"
  r="2"/><circle cx="8" cy="4.5" r="2"/><path d="M7 6.3 5.4 9.7M9 6.3l1.6 3.4M6.5 11.5h3"/></symbol>
<symbol id="i-v2-tools"
  viewBox="0 0 16 16"><path d="M2.5 13.5 8 8M9.5 2.6a3 3 0 0 0 3.9 3.9L11 9 7 5zM4 12l-1.5-1.5"/></symbol>
<symbol id="i-v2-chip" viewBox="0 0 16 16"><rect x="4" y="4" width="8" height="8"
  rx="1.5"/><path d="M6.5 2v2M9.5 2v2M6.5 12v2M9.5 12v2M2 6.5h2M2 9.5h2M12 6.5h2M12 9.5h2"/></symbol>
<symbol id="i-v2-wave" viewBox="0 0 16 16"><path d="M1.5 8h2l1.5-4 2.5 8 2-6 1.5 2h3.5"/></symbol>`);

  // ================= shared helper: drag + pinch =================
  function panZoom(el, apply, { min = 0.5, max = 4 } = {}) {
    const st = { s: 1, x: 0, y: 0 },
      pts = new Map();
    let gesture = null,
      moved = false;
    const rel = e => {
      const r = el.getBoundingClientRect();
      return { x: e.clientX - r.left, y: e.clientY - r.top };
    };
    const cl = s => Math.max(min, Math.min(max, s));
    const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y),
      mid = (a, b) => ({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });
    const start = () => {
      const p = [...pts.values()];
      if (p.length === 1) gesture = { mode: "pan", p0: p[0], x0: st.x, y0: st.y };
      else if (p.length >= 2)
        gesture = {
          mode: "pinch",
          d0: Math.max(1, dist(p[0], p[1])),
          m0: mid(p[0], p[1]),
          s0: st.s,
          x0: st.x,
          y0: st.y,
        };
    };
    el.addEventListener("pointerdown", e => {
      if (e.target.closest(".v2-zoom")) return;
      pts.set(e.pointerId, rel(e));
      if (pts.size === 1) moved = false;
      start();
    });
    el.addEventListener("pointermove", e => {
      if (!pts.has(e.pointerId) || !gesture) return;
      pts.set(e.pointerId, rel(e));
      const touches = [...pts.values()];
      if (gesture.mode === "pan") {
        const dx = touches[0].x - gesture.p0.x,
          dy = touches[0].y - gesture.p0.y;
        if (!moved && Math.hypot(dx, dy) < 7) return;
        if (!moved) {
          moved = true;
          try {
            el.setPointerCapture(e.pointerId);
          } catch (x) {}
        }
        st.x = gesture.x0 + dx;
        st.y = gesture.y0 + dy;
      } else {
        moved = true;
        const scale = cl((gesture.s0 * dist(touches[0], touches[1])) / gesture.d0),
          center = mid(touches[0], touches[1]);
        const wx = (gesture.m0.x - gesture.x0) / gesture.s0,
          wy = (gesture.m0.y - gesture.y0) / gesture.s0;
        st.s = scale;
        st.x = center.x - wx * scale;
        st.y = center.y - wy * scale;
      }
      apply(st, false);
    });
    const up = e => {
      pts.delete(e.pointerId);
      if (pts.size) start();
      else gesture = null;
    };
    el.addEventListener("pointerup", up);
    el.addEventListener("pointercancel", up);
    el.addEventListener(
      "click",
      e => {
        if (moved) {
          e.stopPropagation();
          e.preventDefault();
          moved = false;
        }
      },
      true,
    );
    el.addEventListener(
      "wheel",
      e => {
        e.preventDefault();
        zoomAt(rel(e), e.deltaY < 0 ? 1.15 : 1 / 1.15, false);
      },
      { passive: false },
    );
    function zoomAt(c, f, anim = true) {
      const s = cl(st.s * f);
      const wx = (c.x - st.x) / st.s,
        wy = (c.y - st.y) / st.s;
      st.s = s;
      st.x = c.x - wx * s;
      st.y = c.y - wy * s;
      apply(st, anim);
    }
    return {
      st,
      zoomAt,
      reset(anim = true) {
        st.s = 1;
        st.x = 0;
        st.y = 0;
        apply(st, anim);
      },
      set(s, x, y, anim = true) {
        st.s = cl(s);
        st.x = x;
        st.y = y;
        apply(st, anim);
      },
    };
  }
  const zoomBtns = pre =>
    `<div class="v2-zoom"><button class="ib" data-act="${pre}-z:in"
      aria-label="${esc(F.t("graph.zoom", "Приблизить"))}">${ic("plus")}</button><button class="ib" data-act="${pre}-z:out"
      aria-label="${esc(F.t("graph.zoom_out", "Отдалить"))}">${ic("minus")}</button><button class="ib" data-act="${pre}-z:fit"
      aria-label="${esc(F.t("graph.show_all", "Показать всё"))}">${ic("v2-fit")}</button></div>`;

  // ================= NEIGHBOUR GRAPH =================
  const GT = () => ({
    person: { l: F.t("app.people", "Люди"), one: F.t("data.person_2", "Человек"), ic: "user" },
    doc: { l: F.t("app.documents", "Документы"), one: F.t("app.document", "Документ"), ic: "doc" },
    pc: { l: F.t("graph.pcs", "ПК"), one: F.t("data.computer", "Компьютер"), ic: "monitor" },
    host: { l: F.t("app.hosts", "Хосты"), one: F.t("data.host_2", "Хост"), ic: "server" },
    software: { l: F.t("data.software", "ПО"), one: F.t("graph.program", "Программа"), ic: "app" },
  });
  const CAP = { person: 4, doc: 4, pc: 2, host: 3, software: 3 };
  const TORDER = ["person", "pc", "host", "software", "doc"];
  let GR = null;
  F.on("db", () => {
    GR = null;
  }); // The graph is built from F.db and reset when data changes.
  const shortName = n => {
    const w = n.split(" ");
    return w.length > 1 ? `${w[0][0]}. ${w.slice(1).join(" ")}` : n;
  };
  const shortSw = n => n.replace(/^Microsoft (Office )?/, "").replace(/^Adobe /, "");
  const shortHost = n => {
    const dom = (F.db.project && F.db.project.domain) || "";
    return dom && n.endsWith("." + dom) ? n.split(".")[0] : n;
  };
  // Default graph root: the person with the most relations in the current project's data.
  const graphRoot = () => {
    const g = F.sel.graphAll();
    let best = null,
      bw = -1;
    g.N.forEach((n, k) => {
      if (n.type !== "person") return;
      const w = (g.A.get(k) || new Map()).size;
      if (w > bw) {
        bw = w;
        best = n;
      }
    });
    return best && bw > 0 ? `/p/graph/person/${encodeURIComponent(best.id)}` : null;
  };
  F.v2GraphRoot = graphRoot;
  const shortDoc = n => n.replace(/\.[a-z0-9]+$/i, "").replace(/_/g, " ");
  function graph() {
    if (GR) return GR;
    const nodes = new Map(),
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
        const m = adj.get(x);
        m.set(y, (m.get(y) || 0) + w);
      }
    };
    const hostSet = new Set(demo.hosts.map(h => h.name));
    demo.hosts.forEach(h =>
      add("host", h.name, {
        label: shortHost(h.name),
        full: h.name,
        sub: `${h.role} · ${h.ip}`,
        sev: h.sev === "crit" ? "crit" : "",
        data: h,
      }),
    );
    const pcK = name =>
      hostSet.has(name)
        ? key("host", name)
        : add("pc", name, {
            label: name,
            full: name,
            sub: F.t("data.workstation", "Рабочая станция"),
            data: { name },
          });
    demo.software.forEach((s, i) =>
      add("software", i, {
        label: shortSw(s.name),
        full: s.name,
        sub: `${esc(F.t("about.version", "Версия"))} ${s.ver}${s.eol ? F.t("graph.end_support", " · поддержка завершена") : ""}`,
        sev: s.eol ? "warn" : "",
        data: s,
      }),
    );
    F.db.people.forEach(u => {
      const k = add("person", u.login, {
        label: shortName(u.name),
        full: u.name,
        sub: `${u.role} · ${u.login}`,
        data: u,
      });
      if (u.pc && u.pc !== "-") link(k, pcK(u.pc), 3);
    });
    F.db.pcs.forEach(p => pcK(p.name));
    F.sel
      .docsLive()
      .filter(d => d.status_code === "analyzed")
      .forEach(d => {
        const k = add("doc", d.id, {
          label: shortDoc(d.name),
          full: d.name,
          sub: `${d.ext.toUpperCase()} · ${d.created}`,
          sev: d.findings.includes("secret") ? "crit" : "",
          data: d,
        });
        const pk = d.author ? key("person", d.user.login) : null,
          sk = d.software ? key("software", demo.software.indexOf(d.sw)) : null,
          hk = hostSet.has(d.host) ? key("host", d.host) : null,
          ck = d.author && d.user.pc && d.user.pc !== "-" ? pcK(d.user.pc) : null;
        link(k, pk);
        link(k, sk);
        link(k, hk);
        link(k, ck);
        link(pk, sk);
        link(pk, hk);
        link(ck, sk);
        const inner = [d.folder, d.printer]
          .map(v => (String(v).match(/^\\\\([^\\]+)/) || [])[1])
          .find(x => x && hostSet.has(x));
        if (inner) {
          link(k, key("host", inner));
          link(ck, key("host", inner));
        }
      });
    return (GR = { N: nodes, A: adj, key });
  }
  const entPath = n =>
    n.type === "doc" ? `/p/doc/${n.id}` : `/p/entity/${n.type}/${encodeURIComponent(n.id)}`;
  function neighbors(k, types) {
    const { N: nodes, A: adj } = graph();
    const m = adj.get(k) || new Map();
    const out = [];
    const more = [];
    for (const t of TORDER) {
      if (!types.has(t)) continue;
      const all = [...m.entries()]
        .filter(([x]) => nodes.get(x).type === t)
        .sort(
          (a, b) =>
            b[1] - a[1] ||
            (nodes.get(b[0]).data.findings || []).length - (nodes.get(a[0]).data.findings || []).length,
        );
      all.slice(0, CAP[t]).forEach(([x, w]) => out.push({ k: x, w }));
      if (all.length > CAP[t]) {
        const mk = `more:${t}:${k}`;
        out.push({ k: mk, w: 1, more: { type: t, n: all.length - CAP[t], list: all.map(a => a[0]) } });
        more.push(mk);
      }
    }
    return out;
  }
  const allNeighborsCount = k => (graph().A.get(k) || new Map()).size;

  function shapeSvg(type, r) {
    switch (type) {
      case "person":
        return `<circle class="v2g-sh" r="${r}"/>`;
      case "pc":
        return `<rect class="v2g-sh" x="${-r}" y="${-r * 0.82}" width="${2 * r}"
          height="${1.64 * r}" rx="6"/>`;
      case "host": {
        const q = r * 1.18;
        return `<path class="v2g-sh" d="M0 ${-q}L${q} 0L0 ${q}L${-q} 0Z" stroke-linejoin="round"/>`;
      }
      case "software": {
        const q = r * 1.08;
        return `<polygon class="v2g-sh" points="${[0, 1, 2, 3, 4, 5]
          .map(i => {
            const a = (Math.PI / 3) * i + Math.PI / 6;
            return `${(q * Math.cos(a)).toFixed(1)},${(q * Math.sin(a)).toFixed(1)}`;
          })
          .join(" ")}" stroke-linejoin="round"/>`;
      }
      case "doc":
        return `<path class="v2g-sh"
          d="M${-r * 0.78} ${-r}H${r * 0.3}L${r * 0.78} ${-r * 0.52}V${r}H${-r * 0.78}Z"
          stroke-linejoin="round"/>`;
    }
    return `<circle class="v2g-sh" r="${r}"/>`;
  }
  function nodeSvg(k, isC, more, maxCh) {
    const { N: nodes } = graph();
    if (more) {
      const r = 18;
      return `<g class="v2g-n v2g-more v2-t-${esc(more.type)}" data-k="${esc(k)}" data-act="v2g-more:${esc(k)}"
        role="button" aria-label="${F.t("graph.n_more_l", { n: more.n, l: GT()[more.type].l }, "Ещё {n}: {l}")}">
        <circle class="v2g-hit" r="26"/><circle class="v2g-sh" r="${r}"/><text class="v2g-mn"
          dy=".35em">+${more.n}</text>
        <text class="v2g-l"
          y="${r + 16}">${esc(more.type === "software" || more.type === "pc" ? GT()[more.type].l : GT()[more.type].l.toLowerCase())}</text></g>`;
    }
    const n = nodes.get(k),
      r = isC ? 25 : 18,
      is = isC ? 22 : 17;
    const badge = n.sev
      ? `<g class="v2g-bd ${n.sev}"
        transform="translate(${r * 0.85} ${-r * 0.85})"><circle r="8"/><path d="M0 -4V1M0 3.6v.1"/></g>`
      : "";
    return `<g class="v2g-n v2-t-${esc(n.type)} ${isC ? "ctr" : ""}" data-k="${esc(k)}" data-act="v2g-tap:${esc(k)}"
      role="button" aria-label="${esc(GT()[n.type].one + ": " + n.full)}">
      <circle class="v2g-hit" r="${isC ? 34 : 26}"/>${
        isC
          ? `<circle class="v2g-halo"
        r="${r + 9}"/>`
          : ""
      }${shapeSvg(n.type, r)}
      <use class="v2g-ic" href="#i-${GT()[n.type].ic}" x="${-is / 2}" y="${-is / 2}" width="${is}"
        height="${is}"/>${badge}
      <text class="v2g-l ${isC ? "c" : ""}"
        y="${r + (isC ? 19 : 16)}">${esc(trunc(n.label, isC ? maxCh + 6 : maxCh))}</text></g>`;
  }

  const graphState = () => (state.g = state.g || { hist: [], types: new Set(TORDER), peek: false });
  F.route("/p/graph/:type/:id", {
    title: () => F.t("data.relationship_graph", "Граф связей"),
    tab: "data",
    back: true,
    sub: () => {
      const g = graphState();
      const n = g.hist.length && graph().N.get(g.hist[g.hist.length - 1]);
      return n ? n.full : F.project ? F.project.name : "";
    },
    actions: () => [
      { icon: "info", act: "v2g-help", label: F.t("graph.how_read_graph", "Как читать граф") },
      { icon: "more", act: "menu", label: F.t("app.menu", "Меню") },
    ],
    render: p =>
      F.withStates(
        () => {
          const gs = graphState(),
            { N: nodes, key } = graph(),
            k0 = key(p.type, p.id);
          if (!nodes.has(k0)) {
            const root = graphRoot();
            const rn = root && F.sel.entity("person", F.decode(root.split("/").pop()));
            return ui.empty({
              icon: "graph",
              title: root
                ? F.t("graph.entity_not_found", "Сущность не найдена")
                : F.t("graph.no_relationships_yet", "Связей пока нет"),
              text: root
                ? F.t(
                    "graph.not_project_data_open_graph_from",
                    "Её нет в данных проекта. Откройте граф из карточки человека, хоста или документа.",
                  )
                : F.t(
                    "graph.graph_built_after_projects",
                    "Граф построится после анализа документов проекта.",
                  ),
              action: root
                ? `<button class="btn tonal"
                  data-act="go:${root}">${esc(F.t("graph.open", "Открыть:"))} ${esc(rn ? rn.name : F.t("graph.project_graph", "граф проекта"))}</button>`
                : "",
            });
          }
          if (gs.root !== k0) {
            gs.root = k0;
            gs.hist = [k0];
            gs.peek = false;
          }
          return `
        <div class="chips v2g-chips" role="group"
          aria-label="${esc(F.t("graph.node_types", "Типы узлов"))}">${TORDER.map(
            t => `<button class="chip v2-t-${t} ${gs.types.has(t) ? "on" : ""}"
          data-act="v2g-type:${t}" aria-pressed="${gs.types.has(t)}"><svg class="v2g-chs"
          viewBox="-20 -20 40 40"
          aria-hidden="true">${shapeSvg(t, 15)}</svg>${GT()[t].l}</button>`,
          ).join("")}</div>
        <div class="v2g-trail" id="v2g-trail"></div>
        <div class="v2g-wrap card" id="v2g-wrap">
          <svg class="v2g-svg" id="v2g-svg" role="img"
            aria-label="${esc(F.t("graph.nearest_relationships_graph", "Граф ближайших связей"))}"><g id="v2g-world"
            class="v2g-world"><g id="v2g-e"></g><g id="v2g-nodes"></g></g></svg>
          ${zoomBtns("v2g")}
          <div class="v2g-hint">${ic("swipe")}${esc(F.t("graph.tap_make_center_pinch_zoom", "Тап: сделать центром · щипок: масштаб"))}</div>
        </div>
        <div class="v2g-legend"
          aria-label="${esc(F.t("graph.legend", "Легенда"))}">${TORDER.map(
            t => `<span class="v2-t-${t}"><svg class="v2g-chs"
          viewBox="-20 -20 40 40"
          aria-hidden="true">${shapeSvg(t, 15)}</svg>${GT()[t].one}</span>`,
          ).join("")}<span class="v2g-lg-sev"><svg class="v2g-chs"
          viewBox="-10 -10 20 20"
          aria-hidden="true"><g class="v2g-bd crit"><circle r="8"/><path d="M0 -4V1M0 3.6v.1"/></g></svg>${esc(F.t("graph.risk", "Риск"))}</span><span class="v2g-lg-more"><svg class="v2g-chs"
          viewBox="-20 -20 40 40" aria-hidden="true"><circle class="v2g-sh"
          r="15"/></svg>${esc(F.t("graph.more_links", "Ещё связи"))}</span></div>
        <div id="v2g-list"></div>`;
        },
        {
          loading: "cards",
          empty: {
            icon: "graph",
            title: F.t("graph.no_relationships_yet", "Связей пока нет"),
            text: F.t("graph.graph_built_after_documents", "Граф построится после анализа документов."),
          },
        },
      ),
    mount: (page, p) => {
      if (page.querySelector("#v2g-svg")) graphMount(page);
    },
  });

  function graphMount(page) {
    const gs = graphState(),
      { N: nodes } = graph();
    const wrap = page.querySelector("#v2g-wrap"),
      svg = page.querySelector("#v2g-svg"),
      world = page.querySelector("#v2g-world");
    const width = wrap.clientWidth,
      height = wrap.clientHeight;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    const fsz = parseFloat(getComputedStyle(document.documentElement).fontSize) || 14;
    const maxCh = Math.max(8, Math.round(((15 * 14) / fsz) * (width / 360)));
    const els = new Map();
    let pos = new Map();
    const pz = panZoom(
      svg,
      (st, anim) => {
        world.classList.toggle("anim", !!anim);
        world.style.transform = `translate(${st.x}px,${st.y}px) scale(${st.s})`;
      },
      { min: 0.5, max: 3 },
    );
    gs.pz = pz;
    function layout(center, nb) {
      const P = new Map();
      const cx = width / 2,
        cy = height / 2 - 6;
      P.set(center, { x: cx, y: cy });
      const n = nb.length;
      const R = Math.max(70, Math.min(width / 2 - 40, height / 2 - 50));
      const stagger = n > 7;
      nb.forEach((o, i) => {
        const a = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(1, n);
        const r = stagger && i % 2 ? R * 0.6 : R;
        P.set(o.k, { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) });
      });
      return P;
    }
    function draw(from) {
      const center = gs.hist[gs.hist.length - 1];
      const nb = neighbors(center, gs.types);
      const positions = layout(center, nb);
      const nodesG = page.querySelector("#v2g-nodes"),
        edgesG = page.querySelector("#v2g-e");
      const want = new Set(positions.keys());
      // Leaving nodes.
      for (const [k, el] of els)
        if (!want.has(k)) {
          el.classList.add("gone");
          setTimeout(() => el.remove(), 420);
          els.delete(k);
        }
      // New and existing nodes.
      const moreBy = new Map(nb.filter(o => o.more).map(o => [o.k, o.more]));
      for (const [k, pt] of positions) {
        const isC = k === center;
        let el = els.get(k);
        const html = nodeSvg(k, isC, moreBy.get(k), maxCh);
        if (!el || el.dataset.c !== String(isC) || moreBy.has(k)) {
          const tmp = document.createElementNS("http://www.w3.org/2000/svg", "g");
          tmp.innerHTML = html;
          const ne = tmp.firstElementChild;
          ne.dataset.c = String(isC);
          const start = el ? pos.get(k) : from || pt;
          ne.style.transform = `translate(${start.x}px,${start.y}px)`;
          if (!el) ne.classList.add("new");
          if (el) el.replaceWith(ne);
          else nodesG.appendChild(ne);
          el = ne;
          els.set(k, el);
        }
        const e2 = el;
        requestAnimationFrame(() =>
          requestAnimationFrame(() => {
            e2.classList.remove("new");
            e2.style.transform = `translate(${pt.x}px,${pt.y}px)`;
          }),
        );
      }
      // Centre node on top.
      const ce = els.get(center);
      if (ce) nodesG.appendChild(ce);
      pos = positions;
      // Edges are drawn after the animation.
      edgesG.classList.add("hide");
      const { A: adj } = graph();
      const cm = adj.get(center) || new Map();
      const lines = [];
      nb.forEach(o => {
        const a = positions.get(center),
          b = positions.get(o.k);
        const w = o.more ? 1 : Math.min(4, 1 + Math.log2(o.w));
        lines.push(
          `<line class="${o.more ? "m" : ""}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"
            stroke-width="${w.toFixed(1)}"/>`,
        );
      });
      const real = nb.filter(o => !o.more);
      for (let i = 0; i < real.length; i++)
        for (let j = i + 1; j < real.length; j++) {
          if (nodes.get(real[i].k).type === "doc" || nodes.get(real[j].k).type === "doc") continue;
          const m = adj.get(real[i].k);
          if (m && m.has(real[j].k)) {
            const a = positions.get(real[i].k),
              b = positions.get(real[j].k);
            lines.push(`<line class="x" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`);
          }
        }
      clearTimeout(gs.et);
      gs.et = setTimeout(
        () => {
          edgesG.innerHTML = lines.join("");
          edgesG.classList.remove("hide");
        },
        from ? 430 : 0,
      );
      if (!from) {
        edgesG.innerHTML = lines.join("");
        edgesG.classList.remove("hide");
      }
      drawTrail();
      drawList(center, nb, cm);
      syncBack();
    }
    function drawTrail() {
      const trailEl = page.querySelector("#v2g-trail");
      const hist = gs.hist;
      trailEl.innerHTML =
        hist.length < 2
          ? `<span class="muted">${esc(F.t("graph.center", "Центр:"))} <b>${esc(nodes.get(hist[0]).full)}</b> · ${plural(allNeighborsCount(hist[0]), F.t("graph.link", "связь"), F.t("graph.links", "связи"), F.t("v2.link_many", "связей"))}</span>`
          : hist
              .slice(-4)
              .map((k, i, arr) => {
                const n = nodes.get(k),
                  last = i === arr.length - 1;
                const idx = hist.length - arr.length + i;
                return `${i ? ic("chev", "v2g-tsep") : ""}<button class="v2g-tb v2-t-${n.type} ${last ? "on" : ""}"
                  ${last ? 'aria-current="true"' : `data-act="v2g-jump:${idx}"`}>${ic(GT()[n.type].ic)}<span>${esc(trunc(n.label, 16))}</span></button>`;
              })
              .join("");
      F.$("#tb-s").textContent = F.$("#tb-s").title = nodes.get(hist[hist.length - 1]).full;
    }
    function drawList(center, nb, cm) {
      const listEl = page.querySelector("#v2g-list");
      const by = TORDER.filter(t => gs.types.has(t))
        .map(t => [t, [...cm.entries()].filter(([x]) => nodes.get(x).type === t)])
        .filter(x => x[1].length);
      listEl.innerHTML =
        ui.secH(
          F.t("graph.nearest_relationships", "Ближайшие связи"),
          plural(
            cm.size,
            F.t("graph.node", "узел"),
            F.t("graph.nodes", "узла"),
            F.t("v2.node_many", "узлов"),
          ),
        ) +
        (by.length
          ? `<div class="list">${by
              .map(([t, arr]) => {
                const shown = arr.sort((a, b) => b[1] - a[1]).slice(0, 3);
                return ui.row({
                  lead: `<div class="v2g-lead v2-t-${t}"><svg viewBox="-20 -20 40 40"
                    aria-hidden="true">${shapeSvg(t, 15)}</svg>${ic(GT()[t].ic)}</div>`,
                  title: `${GT()[t].l} · ${arr.length}`,
                  sub: esc(
                    shown.map(([x]) => nodes.get(x).label).join(", ") +
                      (arr.length > 3 ? ` ${esc(F.t("graph.and", "и ещё"))} ${arr.length - 3}` : ""),
                  ),
                  act: `v2g-list:${t}`,
                });
              })
              .join("")}</div>`
          : !allNeighborsCount(center)
            ? ui.empty({
                icon: "graph",
                title: F.t("graph.no_relationships_found", "Связей не найдено"),
                text: F.t(
                  "graph.project_data_node_has_no_links",
                  "В данных проекта у этого узла нет связей с документами, людьми или хостами.",
                ),
              })
            : ui.empty({
                icon: "filter",
                title: F.t("graph.all_types_hidden", "Все типы скрыты"),
                text: F.t(
                  "graph.enable_at_least_one_node_type",
                  "Включите хотя бы один тип узлов в фильтре выше.",
                ),
              }));
    }
    function syncBack() {
      F.onBack(
        gs.peek || gs.hist.length > 1
          ? () => {
              if (gs.peek) {
                closePeek();
                return true;
              }
              if (gs.hist.length > 1) {
                const from = pos.get(gs.hist[gs.hist.length - 1]);
                gs.hist.pop();
                pz.reset();
                draw(from);
                return true;
              }
              return false;
            }
          : null,
      );
    }
    function openPeek(k) {
      F.clearOverlay();
      const n = nodes.get(k);
      const data = n.data;
      let facts = [];
      if (n.type === "person")
        facts = [
          [F.t("graph.department", "Отдел"), data.role],
          [F.t("data.login", "Логин"), data.login],
          [F.t("data.pc", "ПК"), data.pc],
        ];
      if (n.type === "host")
        facts = [
          [F.t("graph.address", "Адрес"), data.ip],
          [F.t("data.role", "Роль"), data.role],
          [F.t("data.software", "ПО"), data.tech],
        ];
      if (n.type === "pc")
        facts = [
          [
            F.t("data.users", "Пользователи"),
            F.db.people
              .filter(u => u.pc === data.name)
              .map(u => u.name)
              .join(", ") || "-",
          ],
        ];
      if (n.type === "software")
        facts = [
          [F.t("about.version", "Версия"), data.ver],
          [F.t("data.documents_count", "Документов"), data.n],
          [
            "CVE",
            data.cve
              ? `${data.cve}${data.eol ? F.t("graph.end_support", " · поддержка завершена") : ""}`
              : F.t("graph.no", "нет"),
          ],
        ];
      if (n.type === "doc")
        facts = [
          [F.t("plugins.author", "Автор"), data.user.name],
          [F.t("graph.created", "Создан"), data.created],
          [F.t("graph.where", "Где"), data.host],
        ];
      const pk = document.createElement("div");
      pk.className = "v2-peek";
      pk.setAttribute("role", "dialog");
      pk.setAttribute("aria-label", F.t("graph.node_preview", "Превью узла"));
      pk.innerHTML = `<div class="v2-peek-h"><div class="v2g-lead v2-t-${n.type}"><svg viewBox="-20 -20 40 40"
        aria-hidden="true">${shapeSvg(n.type, 15)}</svg>${ic(GT()[n.type].ic)}</div>
        <div class="v2-peek-t"><b>${esc(n.full)}</b><span>${GT()[n.type].one} · ${plural(allNeighborsCount(k), F.t("graph.link", "связь"), F.t("graph.links", "связи"), F.t("v2.link_many", "связей"))}</span></div>
        <button class="ib" data-act="v2g-peek-x" aria-label="${esc(F.t("graph.close_preview", "Закрыть превью"))}">${ic("x")}</button></div>
        <div class="v2-peek-f">${facts.map(([a, b]) => `<div><span>${a}</span><b>${esc(b)}</b></div>`).join("")}</div>
        <div class="btnrow"><button class="btn primary"
          data-act="go:${entPath(n)}">${ic("open")}${esc(F.t("graph.open_card", "Открыть карточку"))}</button></div>`;
      F.overlaySlot().appendChild(pk);
      requestAnimationFrame(() => pk.classList.add("show"));
      gs.peek = true;
      syncBack();
    }
    function closePeek() {
      gs.peek = false;
      F.overlaySlot()
        .querySelectorAll(".v2-peek")
        .forEach(x => {
          x.classList.remove("show");
          setTimeout(() => x.remove(), 220);
        });
      syncBack();
    }
    function center(k) {
      const cur = gs.hist[gs.hist.length - 1];
      if (k === cur) {
        gs.peek ? closePeek() : openPeek(k);
        return;
      }
      const from = pos.get(k);
      const i = gs.hist.indexOf(k);
      if (i >= 0) gs.hist = gs.hist.slice(0, i + 1);
      else gs.hist.push(k);
      pz.reset();
      draw(from);
      openPeek(k);
    }
    gs.center = center;
    gs.draw = draw;
    gs.openPeek = openPeek;
    gs.closePeek = closePeek;
    draw(null);
    if (gs.peek) openPeek(gs.hist[gs.hist.length - 1]);
  }
  Object.assign(F.actions, {
    "v2g-tap": k => graphState().center(k),
    "v2g-peek-x": () => graphState().closePeek(),
    "v2g-jump": i => {
      const g = graphState();
      const k = g.hist[+i];
      g.center(k);
    },
    "v2g-type": t => {
      const g = graphState();
      g.types.has(t) ? g.types.delete(t) : g.types.add(t);
      F.page()
        .querySelectorAll(".v2g-chips .chip")
        .forEach(b => {
          const on = g.types.has(b.dataset.act.split(":")[1]);
          b.classList.toggle("on", on);
          b.setAttribute("aria-pressed", on);
        });
      g.draw(null);
    },
    "v2g-z": m => {
      const g = graphState();
      const svg = F.$("#v2g-svg");
      const r = svg.getBoundingClientRect();
      const c = { x: r.width / 2, y: r.height / 2 };
      m === "fit" ? g.pz.reset() : g.pz.zoomAt(c, m === "in" ? 1.35 : 1 / 1.35);
    },
    "v2g-more": mk => {
      const [, t, ...rest] = mk.split(":");
      v2gListSheet(rest.join(":"), t);
    },
    "v2g-list": t => {
      const g = graphState();
      v2gListSheet(g.hist[g.hist.length - 1], t);
    },
    "v2g-help": () =>
      F.sheet({
        title: F.t("graph.how_read_graph", "Как читать граф"),
        html: `<p class="lead">${esc(F.t("graph.selected_entity_center", "В центре выбранная сущность, вокруг только её ближайшие соседи. Толщина линии: сколько документов подтверждают связь. Пунктир: дополнительные связи между соседями."))}</p>
      <div class="list">${TORDER.map(t =>
        ui.row({
          lead: `<div class="v2g-lead v2-t-${t}"><svg viewBox="-20 -20 40 40"
        aria-hidden="true">${shapeSvg(t, 15)}</svg>${ic(GT()[t].ic)}</div>`,
          title: GT()[t].l,
          sub: {
            person: F.t("graph.circle_authors_users_from", "Круг: авторы и пользователи из метаданных"),
            pc: F.t("graph.rectangle_workstations_from", "Прямоугольник: рабочие станции из путей"),
            host: F.t("graph.diamond_servers_subdomains", "Ромб: серверы и поддомены"),
            software: F.t("graph.hexagon_creator_programs", "Шестиугольник: программы-создатели"),
            doc: F.t("graph.sheet_published_files", "Лист: опубликованные файлы"),
          }[t],
        }),
      ).join("")}</div>
      <p class="fhint">${esc(F.t("graph.up_4_nodes_shown_per_type_rest", "По одному типу показывается до 4 узлов, остальные собраны в кружок «+N». Нажмите на него, чтобы выбрать."))}</p>`,
      }),
  });
  function v2gListSheet(ck, title) {
    const { N: nodes, A: adj } = graph();
    const arr = [...(adj.get(ck) || new Map()).entries()]
      .filter(([x]) => nodes.get(x).type === title)
      .sort((a, b) => b[1] - a[1]);
    F.sheet({
      title: `${GT()[title].l} · ${arr.length}`,
      html: `<p class="lead">${F.t("graph.linked_full_tap_make_graph", { full: esc(nodes.get(ck).full) }, "Связаны с «{full}». Нажмите, чтобы сделать центром графа.")}</p><div class="list">${arr
        .slice(0, 60)
        .map(([x, w]) => {
          const n = nodes.get(x);
          return ui.row({
            lead: `<div class="v2g-lead v2-t-${esc(title)}"><svg viewBox="-20 -20 40 40"
              aria-hidden="true">${shapeSvg(title, 15)}</svg>${ic(GT()[title].ic)}</div>`,
            title: esc(n.full),
            sub:
              esc(n.sub) +
              (w > 1
                ? ` · ${plural(w, F.t("graph.link", "связь"), F.t("graph.links", "связи"), F.t("v2.link_many", "связей"))}`
                : ""),
            act: `v2g-pick:${x}`,
          });
        })
        .join(
          "",
        )}</div>${arr.length > 60 ? `<p class="fhint">${F.t("graph.showing_first_60_n", { n: arr.length }, "Показаны первые 60 из {n}.")}</p>` : ""}`,
    });
  }
  F.actions["v2g-pick"] = k => {
    F.closeSheet();
    setTimeout(() => graphState().center(k), 260);
  };

  // ================= GPS MAP: 3D GLOBE =================
  // Canvas 2D with a custom orthographic projection (no libraries); Natural Earth country outlines
  // (ui/data/ne110.js,
  // ne50.js when zoomed in; loaded via <script>, no network). Redraws only on change (no rAF while idle).
  // Points are photos with GPS from the project's documents (F.db.gps); the date is the capture date.
  let GPS = [];
  const gpsDoc = g => g.doc;
  const dms = (v, pos, neg) => {
    const a = Math.abs(v),
      d = Math.floor(a),
      m = Math.floor((a - d) * 60),
      s = ((a - d) * 3600 - m * 60).toFixed(1);
    return `${d}°${String(m).padStart(2, "0")}′${s}″ ${v >= 0 ? pos : neg}`;
  };
  const grad = s => {
    const h = hash(s) % 360;
    return `linear-gradient(135deg, hsl(${h} 45% 42%), hsl(${(h + 50) % 360} 55% 28%))`;
  };
  const RAD = Math.PI / 180;
  const reduced = () => !!(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches);
  // ---- Natural Earth data: { q, c: [[name, iso2, [ring …]]] }, rings are deltas ×q; precompute unit vectors
  // ----
  const NE = (state.ne = state.ne || { lv: {}, wait: {} });
  function neLoad(key) {
    if (NE.lv[key]) return Promise.resolve(NE.lv[key]);
    if (NE.wait[key]) return NE.wait[key];
    return (NE.wait[key] = new Promise(res => {
      const ready = () => {
        const d = (window.FOCA_NE || {})[key];
        if (!d) return res(null);
        NE.lv[key] = prepNE(d);
        res(NE.lv[key]);
      };
      if ((window.FOCA_NE || {})[key]) return ready();
      const sc = document.createElement("script");
      sc.src = `data/${key === "n50" ? "ne50" : "ne110"}.js`;
      sc.async = true;
      sc.onload = ready;
      sc.onerror = () => {
        NE.wait[key] = null;
        res(null);
      };
      document.head.appendChild(sc);
    }));
  }
  function prepNE(d) {
    return d.c.map(([name, iso, rings]) => {
      let mx = 0,
        my = 0,
        mz = 0;
      const R = rings.map(r => {
        const ll = new Float32Array(r.length),
          v = new Float32Array((r.length / 2) * 3);
        let x = 0,
          y = 0;
        for (let i = 0, j = 0; i < r.length; i += 2, j += 3) {
          x += r[i];
          y += r[i + 1];
          const lo = x / d.q,
            la = y / d.q;
          ll[i] = lo;
          ll[i + 1] = la;
          const cl = Math.cos(la * RAD);
          v[j] = cl * Math.cos(lo * RAD);
          v[j + 1] = cl * Math.sin(lo * RAD);
          v[j + 2] = Math.sin(la * RAD);
          mx += v[j];
          my += v[j + 1];
          mz += v[j + 2];
        }
        return { ll, v };
      });
      const l = Math.hypot(mx, my, mz) || 1,
        c = [mx / l, my / l, mz / l];
      let rad = 0;
      R.forEach(({ v }) => {
        for (let j = 0; j < v.length; j += 3)
          rad = Math.max(
            rad,
            Math.acos(Math.max(-1, Math.min(1, v[j] * c[0] + v[j + 1] * c[1] + v[j + 2] * c[2]))),
          );
      });
      return { name, iso, R, c, rad };
    });
  }
  const inRing = (ll, lo, la) => {
    let ins = false;
    for (let i = 0, j = ll.length - 2; i < ll.length; j = i, i += 2) {
      const xi = ll[i],
        yi = ll[i + 1],
        xj = ll[j],
        yj = ll[j + 1];
      if (yi > la !== yj > la && lo < ((xj - xi) * (la - yi)) / (yj - yi) + xi) ins = !ins;
    }
    return ins;
  };
  // Country of a point: inside an outline, otherwise the nearest by vertices (the 110m coastline is
  // simplified,
  // so a port may end up "in the sea").
  const countryOf = (lv, lo, la) => {
    const c0 = lv.find(c => c.R.some(r => inRing(r.ll, lo, la)));
    if (c0) return c0;
    let best = null,
      bd = 4; // At most ~2° away by vertices.
    const k = Math.cos(la * RAD);
    lv.forEach(c =>
      c.R.forEach(r => {
        for (let i = 0; i < r.ll.length; i += 2) {
          const dx = (r.ll[i] - lo) * k,
            dy = r.ll[i + 1] - la,
            d = dx * dx + dy * dy;
          if (d < bd) {
            bd = d;
            best = c;
          }
        }
      }),
    );
    return best;
  };
  const short = p => String(p || "").split(",")[0];
  const globeState = () => (state.m3 = state.m3 || { lon: 31, lat: 42, z: 1, sel: null });

  F.route("/p/map", {
    title: () => F.t("map.gps_map", "Карта GPS"),
    tab: "data",
    back: true,
    sub: () => {
      const n = GPS.length,
        k = (state.m3c || []).length;
      return n
        ? `${plural(n, F.t("map.photo", "фото"), F.t("map.photos", "фото"), F.t("v2.photo_many", "фото"))}${k ? " · " + plural(k, F.t("map.country", "страна"), F.t("map.countries", "страны"), F.t("v2.country_many", "стран")) : ""}`
        : (F.project || {}).name || "";
    },
    render: () =>
      F.withStates(
        () => `
      <div class="card v2m-wrap" id="v2m-wrap">
        <canvas class="v2m-cv" id="v2m-cv" role="img"
          aria-label="${F.t("map.globe_shooting_locations_n_use", { n: plural(GPS.length, F.t("map.photo", "фото"), F.t("map.photos", "фото"), F.t("v2.photo_many", "фото")) }, "Глобус с точками съёмки: {n}. Управление: кнопки масштаба и список точек ниже")}"></canvas>
        <div class="v2m-cnt">${ic("wifi-off")}${esc(F.t("map.offline", "без сети"))}</div>
        ${zoomBtns("v2m")}
        <div class="v2m-attr">© Natural Earth</div>
      </div>
      <div class="card pad v2m-panel" id="v2m-panel">${panelHTML()}</div>
      ${ui.secH(F.t("map.shooting_locations", "Точки съёмки"), GPS.length)}
      <div class="list">${GPS.map((g, i) =>
        ui.row({
          lead: `<div class="v2m-th"
        style="background:${grad(g.name)}">${ic("camera")}</div>`,
          title: esc(g.place),
          sub: `${esc(g.name)} · ${esc(g.dev)}`,
          tail: `<span>${esc(g.date.slice(0, 10))}</span>`,
          act: `v2m-pt:${i}`,
          cls: globeState().sel === i ? "sel" : "",
        }),
      ).join("")}</div>
      <p class="fhint v2m-note">${ic("info")} ${esc(F.t("map.exif_coordinates_can_off_5_50_m", "Координаты из EXIF могут быть неточными на 5-50 м. Публикация фото с GPS промышленных объектов. Находка «Средний» и выше. Карта рисуется на устройстве, координаты не уходят в сеть."))}</p>`,
        {
          empty: {
            icon: "pin",
            title: F.t("map.no_photos_coordinates", "Нет фото с координатами"),
            text: F.t("map.found_images_have_no_exif_gps", "В найденных изображениях нет GPS-меток EXIF."),
          },
        },
      ),
    mount: page => {
      if (page.querySelector("#v2m-cv")) globeMount(page);
    },
    unmount: () => {
      if (state.m3g) {
        state.m3g.stop();
        state.m3g = null;
      }
    },
  });
  function panelHTML() {
    const st = globeState(),
      cs = state.m3c || [],
      places = new Set(GPS.map(g => short(g.place))).size;
    const g = st.sel != null ? GPS[st.sel] : null;
    const chips = `<div class="chips wrap v2m-chips">${cs
      .map(
        c => `<button class="chip ${st.cty === c.iso ? "on" : ""}"
      data-act="v2m-cty:${esc(c.iso || c.name)}">${esc(c.name)} ${c.n}</button>`,
      )
      .join("")}<button class="chip ${st.cty ? "" : "on"}"
      data-act="v2m-z:fit">${esc(F.t("map.whole_world", "Весь мир"))}</button></div>`;
    if (!g)
      return `${chips}<div class="grid g3 v2m-kpi"><div class="card stat"><div class="v">${GPS.length}</div><div class="k">${esc(F.t("map.photos_gps", "фото с GPS"))}</div></div><div class="card stat"><div class="v">${cs.length || "-"}</div><div class="k">${cs.length ? plural(cs.length, F.t("map.country", "страна"), F.t("map.countries", "страны"), F.t("v2.country_many", "стран")).replace(/^\S+\s/, "") : F.t("v2.country_many", "стран")}</div></div><div class="card stat"><div class="v">${places}</div><div class="k">${esc(F.t("map.places", "мест"))}</div></div></div>
      <p class="fhint v2m-hint">${ic("swipe")}${esc(F.t("map.spin_globe_your_finger_double", "Крутите глобус пальцем · двойной тап: приблизить · точка: подробности"))}</p>`;
    const coord = `${g.lat.toFixed(5)}, ${g.lon.toFixed(5)}`;
    return `${chips}<div class="v2m-selc" id="v2m-selc">
      <div class="v2m-selh"><div class="v2m-th lg" style="background:${grad(g.name)}">${ic("camera")}</div>
        <div class="v2m-selb"><b>${esc(g.place)}</b><span>${esc(g.name)}</span><span>${esc(g.dev)} · ${esc(g.date)}</span><span class="pill warn">${ic("pin")}${esc(F.t("map.gps_public_file", "GPS в публичном файле"))}</span></div>
        <button class="ib" data-act="v2m-unsel" aria-label="${esc(F.t("map.close_card", "Закрыть карточку"))}">${ic("x")}</button></div>
      <div class="v2m-coord mono">${dms(g.lat, "N", "S")} · ${dms(g.lon, "E", "W")}</div>
      <div class="btnrow v2m-selbtn"><button class="btn primary"
        data-act="go:/p/doc/${gpsDoc(g)}">${ic("doc")}${esc(F.t("app.document", "Документ"))}</button><button class="btn"
        data-act="copy:${coord}"
        aria-label="${F.t("map.copy_coordinates_coord", { coord }, "Копировать координаты {coord}")}">${ic("copy")}${esc(F.t("data.copy", "Копировать"))}</button></div>
    </div>`;
  }
  const panelRefresh = () => {
    const p = F.$("#v2m-panel");
    if (p) p.innerHTML = panelHTML();
    F.refreshBar && F.refreshBar();
  };

  function globeMount(page) {
    const wrap = page.querySelector("#v2m-wrap"),
      cv = page.querySelector("#v2m-cv"),
      ctx = cv.getContext("2d");
    const st = globeState();
    let W = 0,
      H = 0,
      dpr = 1,
      raf = 0,
      anim = 0,
      hits = [],
      lv = null,
      lv50 = null;
    const css = getComputedStyle(document.documentElement),
      cvar = (k, d) => (css.getPropertyValue(k) || d).trim() || d;
    const ACC = cvar("--accent", "#4c8dff"),
      light = document.documentElement.dataset.theme === "light";
    const stars = Array.from({ length: 110 }, (_, i) => [
      (hash("s" + i) % 1000) / 1000,
      (hash("t" + i) % 1000) / 1000,
      0.4 + (hash("r" + i) % 10) / 10,
    ]);
    function size() {
      W = wrap.clientWidth;
      H = Math.min(460, Math.round(W * 0.95));
      wrap.style.height = H + "px";
      dpr = Math.min(2, window.devicePixelRatio || 1);
      cv.width = Math.round(W * dpr);
      cv.height = Math.round(H * dpr);
      cv.style.width = W + "px";
      cv.style.height = H + "px";
    }
    const R0 = () => Math.min(W, H) * 0.4,
      Rz = () => R0() * st.z;
    // Orthographic projection: unit vector → screen (x, y) and depth z (>0 is the visible side).
    function proj(px, py, pz, R, k = 1) {
      const a = st.lon * RAD,
        f = st.lat * RAD,
        ca = Math.cos(a),
        sa = Math.sin(a),
        cf = Math.cos(f),
        sf = Math.sin(f);
      const u = px * ca + py * sa,
        v = -px * sa + py * ca;
      return [W / 2 + v * R * k, H / 2 - (cf * pz - sf * u) * R * k, sf * pz + cf * u];
    }
    function unproj(sx, sy) {
      const R = Rz(),
        X = (sx - W / 2) / R,
        Y = (H / 2 - sy) / R,
        q = X * X + Y * Y;
      if (q > 1) return null;
      const Z = Math.sqrt(1 - q),
        a = st.lon * RAD,
        f = st.lat * RAD,
        cf = Math.cos(f),
        sf = Math.sin(f);
      const pz = cf * Y + sf * Z,
        u = -sf * Y + cf * Z,
        v = X,
        px = u * Math.cos(a) - v * Math.sin(a),
        py = u * Math.sin(a) + v * Math.cos(a);
      return [Math.atan2(py, px) / RAD, Math.asin(Math.max(-1, Math.min(1, pz))) / RAD];
    }
    const vec = (lo, la) => {
      const c = Math.cos(la * RAD);
      return [c * Math.cos(lo * RAD), c * Math.sin(lo * RAD), Math.sin(la * RAD)];
    };
    const PV = GPS.map(g => vec(g.lon, g.lat));
    // Ring: visible points as is, hidden ones are clamped to the disc edge (horizon).
    function ringPath(v, R) {
      let any = false;
      const a = st.lon * RAD,
        f = st.lat * RAD,
        ca = Math.cos(a),
        sa = Math.sin(a),
        cf = Math.cos(f),
        sf = Math.sin(f),
        cx = W / 2,
        cy = H / 2;
      for (let j = 0; j < v.length; j += 3) {
        const px = v[j],
          py = v[j + 1],
          pz = v[j + 2],
          u = px * ca + py * sa,
          x = -px * sa + py * ca,
          y = cf * pz - sf * u,
          z = sf * pz + cf * u;
        let X = x,
          Y = y;
        if (z < 0) {
          const l = Math.hypot(x, y) || 1;
          X = x / l;
          Y = y / l;
        } else any = true;
        j ? ctx.lineTo(cx + X * R, cy - Y * R) : ctx.moveTo(cx + X * R, cy - Y * R);
      }
      ctx.closePath();
      return any;
    }
    function draw() {
      raf = 0;
      if (!cv.isConnected) return;
      const R = Rz(),
        cx = W / 2,
        cy = H / 2;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      // Space and stars.
      ctx.fillStyle = light ? "#0e1a2e" : "#05080f";
      ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = "#fff";
      stars.forEach(([x, y, r]) => {
        ctx.globalAlpha = 0.25 + r * 0.35;
        ctx.fillRect(x * W, y * H, r, r);
      });
      ctx.globalAlpha = 1;
      // Atmosphere.
      if (R < Math.max(W, H)) {
        const g = ctx.createRadialGradient(cx, cy, R * 0.98, cx, cy, R * 1.12);
        g.addColorStop(0, "rgba(90,160,255,.55)");
        g.addColorStop(1, "rgba(90,160,255,0)");
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(cx, cy, R * 1.12, 0, 7);
        ctx.fill();
      }
      // Ocean.
      const og = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.05, cx, cy, R);
      og.addColorStop(0, "#2d6fb8");
      og.addColorStop(0.6, "#173f73");
      og.addColorStop(1, "#0b2342");
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, 7);
      ctx.fillStyle = og;
      ctx.fill();
      ctx.clip();
      // Land.
      const L = st.z >= 2.5 && lv50 ? lv50 : lv;
      if (L) {
        const ctr = vec(st.lon, st.lat),
          hl = new Set((state.m3c || []).map(c => c.iso || c.name));
        ctx.lineJoin = "round";
        ctx.lineWidth = st.z >= 2.5 ? 0.8 : 0.6;
        for (const c of L) {
          const dot = c.c[0] * ctr[0] + c.c[1] * ctr[1] + c.c[2] * ctr[2];
          if (Math.acos(Math.max(-1, Math.min(1, dot))) - c.rad > Math.PI / 2) continue;
          ctx.beginPath();
          let vis = false;
          for (const r of c.R) vis = ringPath(r.v, R) || vis;
          if (!vis) continue;
          const on = hl.has(c.iso || c.name);
          ctx.fillStyle = on ? "rgba(96,156,255,.78)" : "#3a4a5e";
          ctx.fill();
          ctx.strokeStyle = on ? "rgba(190,215,255,.9)" : "rgba(14,24,38,.9)";
          ctx.stroke();
        }
      }
      // Edge shading.
      const sh = ctx.createRadialGradient(cx - R * 0.2, cy - R * 0.25, R * 0.3, cx, cy, R);
      sh.addColorStop(0, "rgba(0,0,0,0)");
      sh.addColorStop(0.75, "rgba(0,0,0,.12)");
      sh.addColorStop(1, "rgba(0,0,0,.55)");
      ctx.fillStyle = sh;
      ctx.fillRect(cx - R, cy - R, R * 2, R * 2);
      ctx.restore();
      drawPts(R);
    }
    // Points: glowing bars (height ~ photo count); nearby points form a cluster with a count.
    function drawPts(R) {
      const vis = [];
      PV.forEach((p, i) => {
        const s = proj(p[0], p[1], p[2], R);
        if (s[2] > 0.02) vis.push({ i, x: s[0], y: s[1], z: s[2] });
      });
      const used = new Set(),
        cl = [];
      vis.forEach(a => {
        if (used.has(a.i)) return;
        const c = [a];
        used.add(a.i);
        vis.forEach(b => {
          if (!used.has(b.i) && Math.hypot(a.x - b.x, a.y - b.y) < 26) {
            c.push(b);
            used.add(b.i);
          }
        });
        cl.push(c);
      });
      hits = [];
      const labels = [];
      cl.forEach(c => {
        const n = c.length,
          p = PV[c[0].i].map((v, k) => c.reduce((s, q) => s + PV[q.i][k], 0) / n),
          l = Math.hypot(...p);
        const u = p.map(v => v / l),
          base = proj(u[0], u[1], u[2], R),
          h = 0.035 + 0.03 * Math.log2(1 + n),
          top = proj(u[0], u[1], u[2], R, 1 + h);
        const sel = c.some(q => q.i === st.sel),
          fade = Math.min(1, base[2] * 4);
        ctx.globalAlpha = fade;
        const lg = ctx.createLinearGradient(base[0], base[1], top[0], top[1]);
        lg.addColorStop(0, "rgba(255,90,110,.15)");
        lg.addColorStop(1, "rgba(255,120,140,1)");
        ctx.strokeStyle = lg;
        ctx.lineWidth = 3;
        ctx.lineCap = "round";
        ctx.shadowColor = "rgba(255,80,110,.9)";
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.moveTo(base[0], base[1]);
        ctx.lineTo(top[0], top[1]);
        ctx.stroke();
        ctx.shadowBlur = 0;
        ctx.fillStyle = "rgba(255,90,110,.35)";
        ctx.beginPath();
        ctx.ellipse(base[0], base[1], 5, 5 * Math.max(0.3, base[2]), 0, 0, 7);
        ctx.fill();
        const rr = n > 1 ? 11 : 6;
        ctx.shadowColor = "rgba(255,80,110,.9)";
        ctx.shadowBlur = sel ? 16 : 8;
        ctx.fillStyle = "#ff4d6a";
        ctx.beginPath();
        ctx.arc(top[0], top[1], rr, 0, 7);
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.lineWidth = 2;
        ctx.strokeStyle = "#fff";
        ctx.stroke();
        if (sel) {
          ctx.strokeStyle = ACC;
          ctx.lineWidth = 2.5;
          ctx.beginPath();
          ctx.arc(top[0], top[1], rr + 5, 0, 7);
          ctx.stroke();
        }
        if (n > 1) {
          ctx.fillStyle = "#fff";
          ctx.font = "700 11px Inter, sans-serif";
          ctx.textAlign = "center";
          ctx.textBaseline = "middle";
          ctx.fillText(String(n), top[0], top[1] + 0.5);
        }
        ctx.globalAlpha = 1;
        hits.push({ x: top[0], y: top[1], bx: base[0], by: base[1], ids: c.map(q => q.i) });
        labels.push({
          x: top[0] + rr + 5,
          mx: top[0] - rr - 5,
          y: top[1],
          t: short(GPS[c[0].i].place) + (n > 1 ? ` +${n - 1}` : ""),
          z: base[2],
        });
      });
      // Non-overlapping labels (greedy, closest to the centre first).
      ctx.font = "600 11px Inter, sans-serif";
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";
      const boxes = [];
      labels
        .sort((a, b) => b.z - a.z)
        .forEach(l => {
          const w = ctx.measureText(l.t).width + 10,
            bx = l.x + w > W - 52 ? l.mx - w : l.x,
            b = [bx, l.y - 9, w, 18];
          if (
            bx < 2 ||
            boxes.some(
              o => b[0] < o[0] + o[2] && b[0] + b[2] > o[0] && b[1] < o[1] + o[3] && b[1] + b[3] > o[1],
            ) ||
            boxes.length >= 8
          )
            return;
          boxes.push(b);
          ctx.fillStyle = "rgba(8,14,26,.72)";
          ctx.beginPath();
          ctx.roundRect ? ctx.roundRect(b[0], b[1], b[2], b[3], 6) : ctx.rect(b[0], b[1], b[2], b[3]);
          ctx.fill();
          ctx.fillStyle = "#fff";
          ctx.fillText(l.t, b[0] + 5, l.y + 0.5);
        });
    }
    const req = () => {
      if (!raf) raf = requestAnimationFrame(draw);
    };
    const need50 = () => {
      if (st.z >= 2.5 && !lv50)
        neLoad("n50").then(d => {
          if (d) {
            lv50 = d;
            req();
          }
        });
    };
    const setZ = z => {
      st.z = Math.max(0.8, Math.min(40, z));
      need50();
    };
    const stopAnim = () => {
      if (anim) cancelAnimationFrame(anim);
      anim = 0;
    };
    // Smooth "flight" to a point: longitude along the shortest arc; immediate with reduced motion.
    function fly(lon, lat, z, ms = 750) {
      stopAnim();
      lat = Math.max(-80, Math.min(80, lat));
      const l0 = st.lon,
        f0 = st.lat,
        z0 = st.z;
      let dl = ((lon - l0 + 540) % 360) - 180;
      if (reduced() || ms <= 0) {
        st.lon = l0 + dl;
        st.lat = lat;
        setZ(z);
        req();
        return;
      }
      const t0 = performance.now(),
        ease = t => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);
      const step = now => {
        const t = Math.min(1, (now - t0) / ms),
          e = ease(t);
        st.lon = l0 + dl * e;
        st.lat = f0 + (lat - f0) * e;
        setZ(z0 * Math.pow(z / z0, e));
        draw();
        anim = t < 1 ? requestAnimationFrame(step) : 0;
      };
      anim = requestAnimationFrame(step);
    }
    const fitAll = () => {
      if (!PV.length) return [st.lon, st.lat, 1];
      const m = PV.reduce((a, p) => [a[0] + p[0], a[1] + p[1], a[2] + p[2]], [0, 0, 0]),
        l = Math.hypot(...m) || 1,
        c = m.map(v => v / l);
      const spread = Math.max(
        ...PV.map(p => Math.acos(Math.max(-1, Math.min(1, p[0] * c[0] + p[1] * c[1] + p[2] * c[2])))),
      );
      return [Math.atan2(c[1], c[0]) / RAD, Math.asin(c[2]) / RAD, spread < 0.05 ? 6 : spread < 0.2 ? 3 : 1];
    };
    const flyTo = (ids, zmin) => {
      const p = ids.map(i => GPS[i]);
      const lo = p.reduce((s, g) => s + g.lon, 0) / p.length,
        la = p.reduce((s, g) => s + g.lat, 0) / p.length;
      fly(lo, la, Math.max(st.z, zmin));
    };
    // Gestures: drag to rotate (with inertia), pinch to zoom, double tap to fly, tap to select a point.
    const pts = new Map();
    let last = null,
      vel = [0, 0],
      moved = 0,
      pinch = null,
      lastTap = 0,
      lastTapXY = [0, 0];
    const rel = e => {
      const r = cv.getBoundingClientRect();
      return [e.clientX - r.left, e.clientY - r.top];
    };
    cv.addEventListener("pointerdown", e => {
      stopAnim();
      cv.setPointerCapture && cv.setPointerCapture(e.pointerId);
      pts.set(e.pointerId, rel(e));
      moved = 0;
      vel = [0, 0];
      last = { t: performance.now(), p: rel(e) };
      if (pts.size === 2) {
        const [a, b] = [...pts.values()];
        pinch = { d: Math.hypot(a[0] - b[0], a[1] - b[1]), z: st.z };
      }
    });
    cv.addEventListener("pointermove", e => {
      if (!pts.has(e.pointerId)) return;
      const p = rel(e),
        prev = pts.get(e.pointerId);
      pts.set(e.pointerId, p);
      if (pts.size >= 2 && pinch) {
        const [a, b] = [...pts.values()];
        setZ((pinch.z * Math.hypot(a[0] - b[0], a[1] - b[1])) / (pinch.d || 1));
        moved += 10;
        req();
        return;
      }
      const dx = p[0] - prev[0],
        dy = p[1] - prev[1];
      moved += Math.abs(dx) + Math.abs(dy);
      const R = Rz();
      st.lon -= dx / R / RAD;
      st.lat = Math.max(-80, Math.min(80, st.lat + dy / R / RAD));
      const now = performance.now(),
        dt = Math.max(1, now - last.t);
      vel = [dx / dt, dy / dt];
      last = { t: now, p };
      req();
    });
    const up = e => {
      if (!pts.has(e.pointerId)) return;
      const p = rel(e);
      pts.delete(e.pointerId);
      if (pts.size < 2) pinch = null;
      if (pts.size) return;
      if (moved < 8) {
        const now = performance.now();
        if (now - lastTap < 320 && Math.hypot(p[0] - lastTapXY[0], p[1] - lastTapXY[1]) < 30) {
          lastTap = 0;
          const ll = unproj(p[0], p[1]);
          if (ll) fly(ll[0], ll[1], st.z * 2);
          return;
        }
        lastTap = now;
        lastTapXY = p;
        tap(p);
        return;
      }
      // Inertia (none with reduced motion).
      if (reduced() || performance.now() - last.t > 80) return;
      let [vx, vy] = vel;
      const R = Rz();
      const step = () => {
        vx *= 0.92;
        vy *= 0.92;
        if (Math.abs(vx) + Math.abs(vy) < 0.01) {
          anim = 0;
          return;
        }
        st.lon -= (vx * 16) / R / RAD;
        st.lat = Math.max(-80, Math.min(80, st.lat + (vy * 16) / R / RAD));
        draw();
        anim = requestAnimationFrame(step);
      };
      anim = requestAnimationFrame(step);
    };
    cv.addEventListener("pointerup", up);
    cv.addEventListener("pointercancel", up);
    cv.addEventListener(
      "wheel",
      e => {
        e.preventDefault();
        setZ(st.z * (e.deltaY < 0 ? 1.15 : 1 / 1.15));
        req();
      },
      { passive: false },
    );
    function tap(p) {
      let best = null,
        bd = 26;
      hits.forEach(h => {
        const d = Math.min(Math.hypot(p[0] - h.x, p[1] - h.y), Math.hypot(p[0] - h.bx, p[1] - h.by));
        if (d < bd) {
          bd = d;
          best = h;
        }
      });
      if (!best) return;
      if (best.ids.length === 1) {
        select(best.ids[0]);
        return;
      }
      const g = best.ids.map(i => GPS[i]),
        same = g.every(x => Math.abs(x.lat - g[0].lat) < 1e-4 && Math.abs(x.lon - g[0].lon) < 1e-4);
      if (same || st.z >= 39) {
        F.sheet({
          title: `${plural(best.ids.length, F.t("map.point", "точка"), F.t("map.points", "точки"), F.t("v2.point_many", "точек"))} ${esc(F.t("map.nearby", "рядом"))}`,
          html: `<div class="list">${best.ids
            .map(i =>
              ui.row({
                lead: `<div class="v2m-th"
            style="background:${grad(GPS[i].name)}">${ic("camera")}</div>`,
                title: esc(GPS[i].place),
                sub: `${esc(GPS[i].name)} · ${esc(GPS[i].date)}`,
                act: `v2m-pt:${i}`,
              }),
            )
            .join("")}</div>`,
        });
        return;
      }
      flyTo(best.ids, st.z * 2.5);
    }
    function select(i, flyToo) {
      st.sel = i;
      panelRefresh();
      if (flyToo) flyTo([i], Math.max(st.z, 4));
      else req();
    }
    const ro = window.ResizeObserver
      ? new ResizeObserver(() => {
          if (wrap.clientWidth && wrap.clientWidth !== W) {
            size();
            req();
          }
        })
      : null;
    if (ro) ro.observe(wrap);
    state.m3g = {
      stop: () => {
        stopAnim();
        if (raf) cancelAnimationFrame(raf);
        raf = 0;
        if (ro) ro.disconnect();
      },
      zoom: f => {
        const z = st.z * f;
        if (reduced()) {
          setZ(z);
          req();
        } else fly(st.lon, st.lat, Math.max(0.8, Math.min(40, z)), 280);
      },
      fit: () => {
        st.cty = null;
        const [lo, la, z] = fitAll();
        fly(lo, la, z);
        panelRefresh();
      },
      select,
      flyTo,
      get z() {
        return st.z;
      },
      get hits() {
        return hits.map(h => ({ x: h.x, y: h.y, n: h.ids.length }));
      },
    };
    size();
    if (!state.m3init) {
      state.m3init = true;
      const [lo, la, z] = fitAll();
      Object.assign(st, { lon: lo, lat: la, z: Math.min(z, 1.6) });
    }
    neLoad("n110").then(d => {
      lv = d;
      if (d && !state.m3c) {
        // Countries with photos: point-in-polygon against the 110m outlines.
        const m = new Map();
        GPS.forEach(g => {
          const c = countryOf(d, g.lon, g.lat);
          const k = c ? c.iso || c.name : "?";
          const e = m.get(k) || {
            iso: c ? c.iso : "",
            name: c ? c.name : F.t("map.offshore", "Вне суши"),
            n: 0,
          };
          e.n++;
          m.set(k, e);
        });
        state.m3c = [...m.values()].sort((a, b) => b.n - a.n);
        panelRefresh();
      }
      need50();
      req();
    });
    req();
  }
  Object.assign(F.actions, {
    "v2m-z": m => {
      const g = state.m3g;
      if (!g) return;
      if (m === "fit") g.fit();
      else g.zoom(m === "in" ? 1.6 : 1 / 1.6);
    },
    "v2m-pt": i => {
      const g = state.m3g;
      if (F.closeSheet) F.closeSheet();
      if (g) {
        g.select(+i, true);
        const p = F.$("#v2m-wrap");
        if (p && p.scrollIntoView)
          p.scrollIntoView({ block: "start", behavior: reduced() ? "auto" : "smooth" });
      } else {
        globeState().sel = +i;
        panelRefresh();
      }
    },
    "v2m-unsel": () => {
      globeState().sel = null;
      panelRefresh();
      if (state.m3g) state.m3g.select(null);
    },
    "v2m-cty": iso => {
      const st = globeState();
      st.cty = iso;
      const ids = [];
      GPS.forEach((g, i) => {
        const c = state.ne.lv.n110 && countryOf(state.ne.lv.n110, g.lon, g.lat);
        if (c && (c.iso || c.name) === iso) ids.push(i);
      });
      if (ids.length && state.m3g) state.m3g.flyTo(ids, 3);
      panelRefresh();
    },
  });

  // ================= TIMELINE =================
  const TL = () => (state.tl = state.tl || { per: "all", from: 2016, to: 2025 });
  let YEARS = [];
  const PERIODS = () => [
    ["all", F.t("timeline.all_time", "Всё время")],
    ["5", F.t("timeline.5_years", "5 лет")],
    ["3", F.t("timeline.3_years", "3 года")],
    ["custom", F.t("launch.profile_custom", "Свой")],
  ];
  /** Pill style per timeline event severity. */
  const EV_PILL = { crit: "crit", warn: "warn", ok: "ok" };
  let EVENTS = []; // Events come from document dates (F.db.events).
  const tlRange = () => {
    const t = TL();
    const last = YEARS[YEARS.length - 1];
    if (t.per === "5") return [last - 4, last];
    if (t.per === "3") return [last - 2, last];
    if (t.per === "custom") return [t.from, t.to];
    return [YEARS[0], last];
  };
  const DAYS = () => [
    F.t("timeline.mon", "Пн"),
    F.t("timeline.tue", "Вт"),
    F.t("timeline.wed", "Ср"),
    F.t("timeline.thu", "Чт"),
    F.t("timeline.fri", "Пт"),
    F.t("timeline.sat", "Сб"),
    F.t("timeline.sun", "Вс"),
  ];
  function heat(docs) {
    const M = Array.from({ length: 7 }, () => Array(24).fill(0));
    // Taken as is from metadata: weekday and hour are the document's local time, without adjustments.
    docs.forEach(d => {
      const [dd, mm, yy] = d.created.slice(0, 10).split(".").map(Number);
      const wd = (new Date(yy, mm - 1, dd).getDay() + 6) % 7;
      const h = +d.created.slice(11, 13);
      M[wd][h]++;
    });
    return M;
  }
  F.route("/p/timeline", {
    title: () => F.t("timeline.timeline", "Таймлайн"),
    tab: "data",
    back: true,
    render: () =>
      F.withStates(
        () => {
          if (!YEARS.length)
            return ui.empty({
              icon: "history",
              title: F.t("timeline.no_dates", "Нет дат"),
              text: F.t(
                "timeline.projects_analyzed_documents_have",
                "В разобранных документах проекта пока нет дат создания.",
              ),
            });
          const tl = TL();
          const [fromYear, toYear] = tlRange();
          const docs = F.sel.timeline().docs.filter(d => d.year >= fromYear && d.year <= toYear);
          const ys = YEARS.filter(y => y >= fromYear && y <= toYear);
          const cnt = ys.map(y => docs.filter(d => d.year === y).length);
          const max = Math.max(1, ...cnt);
          const heatmap = heat(docs);
          const hm = Math.max(1, ...heatmap.flat());
          const tot = docs.length;
          const wh = F.sel.timeline().workHours || { from: 8, to: 19, tz: "" };
          const work = heatmap
            .slice(0, 5)
            .reduce((s, r) => s + r.slice(wh.from, wh.to).reduce((x, y) => x + y, 0), 0); // Weekdays within working hours from settings.
          const byH = Array.from({ length: 24 }, (_, h) => heatmap.reduce((x, r) => x + r[h], 0));
          const mh = Math.max(...byH);
          const hot = byH.map((v, h) => (v >= mh * 0.5 && mh ? h : -1)).filter(h => h >= 0);
          const peak = hot.length ? `${hot[0]}-${hot[hot.length - 1] + 1}` : "-";
          const wkend = heatmap
            .slice(5)
            .flat()
            .reduce((x, y) => x + y, 0);
          const peakY = ys[cnt.indexOf(Math.max(...cnt))];
          const ev = EVENTS.filter(e => e.y >= fromYear && e.y <= toYear).reverse();
          return `
        <div class="seg v2-segg v2t-per" role="radiogroup"
          aria-label="${esc(F.t("timeline.period", "Период"))}">${PERIODS()
            .map(
              ([k, l]) => `<button class="${tl.per === k ? "on" : ""}"
          role="radio" aria-checked="${tl.per === k}"
          data-act="v2t-per:${k}">${k === "custom" && tl.per === "custom" ? `${tl.from}-${tl.to}` : l}</button>`,
            )
            .join("")}</div>
        <div class="grid g3 v2t-stats">
          <div class="card stat"><div class="k">${esc(F.t("data.documents_count", "Документов"))}</div><div class="v">${fmt(tot)}</div><div class="d">${fromYear}-${toYear}</div></div>
          <div class="card stat"><div class="k">${esc(F.t("timeline.peak", "Пик"))}</div><div class="v">${peakY}</div><div class="d">${Math.max(...cnt)} ${esc(F.t("data.docs", "док."))}</div></div>
          <div class="card stat"><div class="k">${esc(F.t("timeline.events", "Событий"))}</div><div class="v">${ev.length}</div><div class="d">${esc(F.t("timeline.feed", "в ленте"))}</div></div>
        </div>
        ${ui.secH(F.t("timeline.documents_year", "Документы по годам"), F.t("timeline.tap_bar", "нажмите на столбик"))}
        <div class="card v2t-bars" style="--n:${ys.length}"
          role="list">${ys
            .map(
              (y, i) => `<button class="v2t-bar ${state.tlSel === y ? "on" : ""}" role="listitem"
          data-act="v2t-year:${y}"
          aria-label="${y}: ${plural(cnt[i], F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов"))}"><span class="v2t-bn">${cnt[i]}</span><span class="v2t-bc"><i style="height:${Math.max(4, (cnt[i] / max) * 100)}%"></i></span><span class="v2t-by"><span class="l">${y}</span><span class="s">’${String(y).slice(2)}</span></span></button>`,
            )
            .join("")}</div>
        ${F.ins ? F.ins.lanesHtml() : ""}
        ${
          (F.ins && F.ins.heatHtml(wh)) ||
          `${ui.secH(F.t("data.activity_hours", "Часы активности"), F.t("timeline.creation_time", "по времени создания"))}
        <div class="card pad v2t-heat">
          <div class="v2t-hg" role="img" aria-label="${esc(F.t("timeline.heat_map_weekdays_hour", "Тепловая карта: дни недели по часам"))}">
            <span></span>${Array.from({ length: 24 }, (_, h) => `<span class="v2t-hh">${h % 6 === 0 ? h : ""}</span>`).join("")}
            ${heatmap
              .map(
                (r, d) =>
                  `<span class="v2t-hd">${DAYS()[d]}</span>${r
                    .map(
                      (v, h) => `<i style="--v:${((v / hm) * 100).toFixed(0)}%"
              title="${DAYS()[d]} ${h}:00 · ${v}"></i>`,
                    )
                    .join("")}`,
              )
              .join("")}
          </div>
          <div class="v2t-hl"><span>${esc(F.t("timeline.hours_documents_local_time", "Часы: местное время документа"))}</span><span class="v2t-hlg">${esc(F.t("timeline.less", "меньше"))}<i style="--v:0%"></i><i style="--v:30%"></i><i style="--v:60%"></i><i style="--v:100%"></i>${esc(F.t("timeline.more", "больше"))}</span></div>
          <div class="v2t-out">
            <div>${ic("clock")}<span><b>${F.t("timeline.document_creation_peaks_at_peak", { peak }, "Пик создания документов: {peak} ч")}</b>${wh.tz ? ` ${F.t("timeline.client_time_zone_tz", { tz: esc(wh.tz) }, "(часовой пояс заказчика {tz})")}` : ""}</span></div>
            <div>${ic("v2-cal")}<span><b>${F.t("timeline.working_hours_from", { from: wh.from }, "Рабочие часы {from}-")}${wh.to}</b> ${F.t("timeline.weekdays_tot_documents", { tot: tot ? Math.round((work / tot) * 100) : 0 }, "в будни: {tot}% документов")}</span></div>
            <div>${ic("moon")}<span>${F.t("timeline.weekends_tot_activity", { tot: tot ? Math.round((wkend / tot) * 100) : 0 }, "Выходные: {tot}% активности")}</span></div>
          </div>
        </div>`
        }
        ${ui.secH(F.t("timeline.event_feed", "Лента событий"), ev.length)}
        ${ev.length ? `<div class="v2t-feed">${ev.map(e => `<div class="v2t-ev ${e.sev || ""}"><div class="v2t-dot">${ic(e.ic)}</div><div class="v2t-eb"><div class="v2t-et"><span class="mono">${e.m}.${e.y}</span><span class="pill ${EV_PILL[e.sev] || "mute"}">${e.k}</span></div><div class="v2t-tt">${esc(e.t)}</div><div class="v2t-ts">${esc(e.s)}</div></div></div>`).join("")}</div>` : ui.empty({ icon: "history", title: F.t("timeline.no_events_period", "Нет событий за период"), text: F.t("timeline.widen_period_see_changes", "Расширьте период, чтобы увидеть изменения.") })}`;
        },
        {
          loading: "cards",
          empty: {
            icon: "history",
            title: F.t("timeline.no_dates", "Нет дат"),
            text: F.t("timeline.no_creation_dates_were_found", "В документах не нашлось дат создания."),
          },
        },
      ),
    // Columns are ≥ 44 px: if there are more years than fit, the card scrolls to show the latest years.
    mount(page) {
      const c = page.querySelector(".v2t-bars");
      if (c && c.scrollWidth > c.clientWidth) c.scrollLeft = c.scrollWidth;
    },
  });
  // Inline validation of the alert channel fields: errors stay under their field until the next save.
  const moErrs = {};
  const moErr = k =>
    moErrs[k] ? `<p class="fhint err" id="v2mo-${k}-err" role="alert">${esc(moErrs[k])}</p>` : "";
  const moErrAttr = k => (moErrs[k] ? ` aria-invalid="true" aria-describedby="v2mo-${k}-err"` : "");
  const alertKeys = () => (F.db.settings || {}).keys || {};
  const alertCfgNow = () => state.alertCfg || (F.db.settings || {}).alerts || {};
  const CHANNEL = () => ({ telegram: "Telegram", webhook: "Webhook" });
  /** Returns the field errors of a channel: `vals` holds the typed values (empty = keep the stored one). */
  const channelErrors = (ch, vals) => {
    const e = {};
    if (ch === "telegram") {
      const hasTok = vals.tok || (alertKeys().tg_bot || {}).status === "ok";
      if (!hasTok) e.tok = F.t("monitor.err_token_required", "Введите токен бота от @BotFather.");
      else if (vals.tok && !/^\d{5,}:[\w-]{20,}$/.test(vals.tok))
        e.tok = F.t("monitor.err_token_format", "Токен выглядит как 123456789:AA… (цифры, двоеточие, ключ).");
      if (!vals.chat) e.chat = F.t("monitor.err_chat_required", "Введите ID чата или @имя канала.");
      else if (!/^(-?\d+|@[A-Za-z][\w]{3,})$/.test(vals.chat))
        e.chat = F.t("monitor.err_chat_format", "ID чата: число (например, -1001987654321) или @имя канала.");
    } else {
      const hasUrl = vals.url || (alertKeys().webhook || {}).status === "ok";
      if (!hasUrl) e.url = F.t("monitor.err_url_required", "Введите адрес webhook.");
      else if (vals.url && !/^https?:\/\/[^\s/]+/i.test(vals.url))
        e.url = F.t("monitor.err_url_format", "Адрес должен начинаться с https://");
    }
    return e;
  };
  const showErrors = (keys, e) => {
    keys.forEach(k => delete moErrs[k]);
    Object.assign(moErrs, e);
    F.render(true);
    const first = keys.find(k => e[k]);
    if (first) {
      const el = F.$("#v2mo-" + first);
      if (el) el.focus();
    }
    return !first;
  };

  Object.assign(F.actions, {
    "v2t-per": k => {
      if (k !== "custom") {
        TL().per = k;
        state.tlSel = null;
        F.render(true);
        return;
      }
      const tl = TL();
      const years = YEARS.map(y => ({ v: String(y), t: String(y) }));
      const yearPick = (id, title, v) => ui.select({ id, value: String(v), title, options: years });
      F.sheet({
        title: F.t("timeline.custom_period", "Свой период"),
        html: `<label class="flabel" for="v2t-f">${esc(F.t("timeline.from_year", "С года"))}</label>${yearPick(
          "v2t-f",
          F.t("timeline.from_year", "С года"),
          tl.from,
        )}<label class="flabel"
          for="v2t-t">${esc(F.t("timeline.year", "По год"))}</label>${yearPick("v2t-t", F.t("timeline.year", "По год"), tl.to)}<p class="fhint">${esc(F.t("timeline.dates_come_from_metadata", "Даты берутся из метаданных: создание, изменение, печать."))}</p>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary"
          data-act="v2t-apply">${esc(F.t("timeline.apply", "Применить"))}</button>`,
      });
    },
    "v2t-apply": () => {
      const t = TL();
      let f = +F.$("#v2t-f").value,
        to = +F.$("#v2t-t").value;
      if (f > to) [f, to] = [to, f];
      Object.assign(t, { per: "custom", from: f, to });
      F.closeSheet();
      F.render(true);
    },
    "v2t-year": y => {
      y = +y;
      state.tlSel = y;
      F.page()
        .querySelectorAll(".v2t-bar")
        .forEach(b => b.classList.toggle("on", b.dataset.act === "v2t-year:" + y));
      const docs = F.sel.timeline().docs.filter(d => d.year === y);
      F.sheet({
        title: `${y} · ${plural(docs.length, F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов"))}`,
        onClose: () => {
          state.tlSel = null;
          F.page() &&
            F.page()
              .querySelectorAll(".v2t-bar")
              .forEach(b => b.classList.remove("on"));
        },
        html: `<div class="list">${docs
          .slice(0, 25)
          .map(d =>
            ui.row({
              lead: `<span class="ext ${esc(d.ext)}">${esc(d.ext)}</span>`,
              title: esc(d.name),
              sub: `${esc(d.created)} · ${esc(d.user.login)}`,
              act: `go:/p/doc/${d.id}`,
            }),
          )
          .join(
            "",
          )}</div>${docs.length > 25 ? `<p class="fhint">${F.t("timeline.showing_25_n_full_list_data", { n: docs.length }, "Показаны 25 из {n}. Полный список: в разделе «Данные → Документы».")}</p>` : ""}`,
        footer: `<button class="btn tonal"
          data-act="go:/p/data/docs">${ic("filter")}${esc(F.t("timeline.all_documents", "Все документы за"))} ${y}</button>`,
      });
    },
  });

  // ================= MONITORING and WHAT CHANGED =================
  // Monitoring is per project and survives reloads: settings.monitor[project]; off by default for projects
  // without scans.
  const MON = () => {
    const pid = (F.db.project || {}).id;
    if (!state.mon || state.monP !== pid) {
      const had = F.sel.scans().length > 0;
      const saved = ((F.db.settings || {}).monitor || {})[pid] || {};
      state.mon = {
        mode: had ? "weekly" : "off",
        time: "03:00",
        wifi: true,
        charge: true,
        tg: had,
        hook: false,
        what: "crit",
        ...saved,
        days: new Set(saved.days || [1]),
      };
      state.monP = pid;
    }
    return state.mon;
  };
  const monSave = () => {
    const m = MON();
    F.api.settings_set({ monitor: { [state.monP]: { ...m, days: [...m.days] } } });
  };
  // Next run, computed from "today" and the selected weekdays.
  const monNext = m => {
    const t0 = new Date(F.sel.scope.today + "T12:00:00");
    for (let k = 1; k <= 7; k++) {
      const d = new Date(t0.getTime() + k * 864e5);
      const wd = ((d.getDay() + 6) % 7) + 1;
      if (m.mode === "daily" || m.days.has(wd))
        return k === 1
          ? `${esc(F.t("timeline.tomorrow", "завтра, ~"))}${m.time}`
          : `${DAYS()[wd - 1].toLowerCase()}, ${String(d.getDate()).padStart(2, "0")}.${String(d.getMonth() + 1).padStart(2, "0")}, ~${m.time}`;
    }
    return "-";
  };
  F.on("db", e => {
    if (e.kind === "project" || e.kind === "reset") {
      state.mon = null;
      state.alertCfg = null;
      state.alertPid = null;
      state.trend = null;
    } else if (e.kind === "scan" || e.kind === "settings") {
      state.alertCfg = null;
      state.trend = null;
    }
  });
  const RULE_LABELS = () => ({
    new_host: F.t("monitor.new_host_scope", "Новый хост в скоупе"),
    new_port: F.t("monitor.new_open_port_dangerous_service", "Новый открытый порт / опасный сервис"),
    doc_secret: F.t("monitor.secret_new_document", "Секрет в новом документе"),
    doc_pii: F.t("monitor.personal_data_document", "Персональные данные (ПДн) в документе"),
    doc_gps: F.t("monitor.gps_coordinates_new_media", "GPS-координаты в новом медиа"),
    tls_expiry: F.t("monitor.tls_certificate_expiring_or", "Истечение или просрочка TLS-сертификата"),
    dangling_cname: F.t("monitor.dangling_cname_subdomain", "Висящий CNAME (subdomain takeover)"),
    ct_new_cert: F.t("monitor.new_certificate_ct_logs", "Новый сертификат в CT-логах"),
    risk_rise: F.t("monitor.risk_score_above_threshold_spike", "Рост риск-скора выше порога / скачок"),
  });
  const SEV_NAMES = () => [
    ["crit", F.t("monitor.crit", "Крит")],
    ["high", F.t("monitor.high", "Выс.")],
    ["warn", F.t("monitor.med", "Сред.")],
    ["low", F.t("monitor.low", "Низ.")],
    ["info", F.t("sev.info", "Инфо")],
  ];
  const WH_KINDS = [
    ["generic", "Generic JSON"],
    ["slack", "Slack"],
    ["mattermost", "Mattermost"],
    ["discord", "Discord"],
  ];
  function loadMonitorData(pid) {
    if (!pid || !F.api.alert_rules_get || !F.api.risk_trend_get) return;
    state.alertPid = pid;
    Promise.all([
      F.api.alert_rules_get({ project: pid }).catch(() => null),
      F.api.risk_trend_get({ project: pid, limit: 20 }).catch(() => null),
    ]).then(([cfg, tr]) => {
      if (state.alertPid !== pid) return;
      if (cfg) state.alertCfg = cfg;
      if (tr) state.trend = tr;
      if (F.current && F.current() === "/p/monitor") F.render(true);
    });
  }
  function renderRiskTrendHTML(tr, threshold) {
    if (!tr || !tr.points || !tr.points.length) return "";
    const pts = tr.points;
    const W = 320,
      H = 96,
      PX = 16,
      PY = 12;
    const xOf = i => (pts.length === 1 ? W / 2 : PX + (i * (W - PX * 2)) / (pts.length - 1));
    const yOf = r => PY + ((100 - Math.max(0, Math.min(100, Number(r || 0)))) * (H - PY * 2)) / 100;
    const poly = pts.map((p, i) => `${xOf(i).toFixed(1)},${yOf(p.risk).toFixed(1)}`).join(" ");
    const th = threshold > 0 ? yOf(threshold).toFixed(1) : null;
    const dirLbl =
      tr.direction === "up"
        ? `+${tr.delta} ↑`
        : tr.direction === "down"
          ? `${tr.delta} ↓`
          : tr.direction === "flat"
            ? F.t("monitor.no_change", "без сдвига")
            : F.t("monitor.baseline_scan", "базовый скан");
    const dirCls = tr.direction === "up" ? "crit" : tr.direction === "down" ? "ok" : "mute";
    return `<div class="card pad v2mo-chart">
      <div class="v2mo-lrow"><b>${esc(F.t("monitor.risk_trend", "Динамика риска"))}</b><span class="pill ${dirCls}">${F.t("monitor.current_current_peak_peak", { current: esc(tr.current ?? "-"), peak: esc(tr.peak ?? "-") }, "Текущий: {current} · Пик: {peak} ·")} ${esc(dirLbl)}</span></div>
      <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(F.t("monitor.risk_score_chart_scan", "График риск-скора по сканам"))}">
        ${th ? `<line x1="${PX}" y1="${th}" x2="${W - PX}" y2="${th}" stroke="var(--warn)" stroke-dasharray="3 3" stroke-width="1"/>` : ""}
        ${pts.length > 1 ? `<polyline fill="none" stroke="var(--accent)" stroke-width="2" points="${poly}"/>` : ""}
        ${pts
          .map(
            (p, i) =>
              `<circle cx="${xOf(i).toFixed(1)}" cy="${yOf(p.risk).toFixed(1)}" r="3.5" fill="${p.complete ? "var(--accent)" : "var(--card)"}" stroke="var(--accent)" stroke-width="2"><title>${esc(p.time || p.scan_id)}: ${p.risk}</title></circle>`,
          )
          .join("")}
      </svg>
    </div>`;
  }
  const monStatusHTML = st => {
    if (!st || !st.status) return "";
    const meta = {
      done: ["ok", F.t("common.done", "Готово")],
      budget: ["warn", F.t("monitor.background_limit", "Лимит фона")],
      cancelled: ["warn", F.t("monitor.stopped", "Остановлен")],
      workmanager: ["warn", F.t("monitor.stopped_system", "Остановлен системой")],
      busy: ["mute", F.t("monitor.skipped_busy", "Пропущен (занят)")],
      error: ["bad", F.t("app.error", "Ошибка")],
    }[st.status] || ["mute", String(st.status)];
    const when = st.at ? esc(String(st.at).replace("T", " ").slice(0, 16)) : "-";
    const prof =
      st.profile === "std"
        ? F.t("launch.profile_std", "Стандартный")
        : F.t("launch.profile_passive", "Пассивный");
    const mode = st.headless
      ? F.t("monitor.headless_background", "Автономный фон")
      : F.t("monitor.app", "В приложении");
    const diff =
      st.status === "done"
        ? ` ${F.t("monitor.added_docs_docs_added_findings", { added_docs: fmt(st.added_docs || 0), added_findings: fmt(st.added_findings || 0) }, "· документы: +{added_docs} · находки: +{added_findings}")}`
        : "";
    const resume = ["budget", "cancelled", "workmanager", "error"].includes(st.status)
      ? `<div class="btnrow"><button class="btn sm tonal" data-act="go:/p/scan">${ic("play")}${esc(F.t("monitor.open_scan", "Открыть скан"))}</button></div>`
      : "";
    return `<div class="card pad v2mo-last"><div class="v2mo-lrow"><b>${esc(F.t("monitor.last_scheduled_run", "Последний плановый запуск"))}</b><span class="pill ${meta[0]}">${esc(meta[1])}</span></div><div class="s">${when} · ${prof} · ${mode}${diff}</div>${st.error ? `<div class="s muted">${esc(st.error)}</div>` : ""}${resume}</div>`;
  };
  let SCANS = []; // Single scan history (F.db.scans).
  F.route("/p/monitor", {
    title: () => F.t("monitor.monitoring", "Мониторинг"),
    tab: "overview",
    back: true,
    render: () =>
      F.withStates(
        () => {
          const mon = MON();
          const on = mon.mode !== "off";
          const next = mon.mode === "off" ? "-" : monNext(mon);
          const pid = (F.db.project || {}).id;
          const monSt = ((F.db.settings || {}).monitor_status || {})[pid];
          const acfg = state.alertCfg || (F.db.settings || {}).alerts || {};
          const keys = (F.db.settings || {}).keys || {};
          const tgKey = keys.tg_bot || {};
          const whKey = keys.webhook || {};
          const tg = acfg.telegram || {};
          const wh = acfg.webhook || {};
          const rulesObj = acfg.rules || {};
          const availRules = acfg.available_rules || Object.keys(RULE_LABELS()).map(id => ({ id }));
          return `
        <div class="card pad v2mo-head ${on ? "on" : ""}">
          <div class="lead-ic">${ic(on ? "history" : "pause")}</div>
          <div class="v2mo-ht"><b>${on ? F.t("monitor.repeat_scans_enabled", "Повторные сканы включены") : F.t("monitor.monitoring_disabled", "Мониторинг выключен")}</b><span>${on ? `${esc(F.t("monitor.next_run", "Следующий запуск:"))} ${next}` : F.t("monitor.changes_not_tracked", "Изменения не отслеживаются")}</span></div>
        </div>
        ${monStatusHTML(monSt)}
        ${renderRiskTrendHTML(state.trend, acfg.risk_threshold)}
        ${ui.secH(F.t("monitor.schedule", "Расписание"))}
        <div class="seg v2-segg" role="radiogroup" aria-label="${esc(F.t("monitor.frequency", "Частота"))}">${[
          ["off", F.t("monitor.off", "Выкл")],
          ["daily", F.t("monitor.daily", "Ежедневно")],
          ["weekly", F.t("monitor.weekly", "Еженедельно")],
        ]
          .map(
            ([k, l]) =>
              `<button class="${mon.mode === k ? "on" : ""}" role="radio"
                aria-checked="${mon.mode === k}" data-act="v2mo-mode:${k}">${l}</button>`,
          )
          .join("")}</div>
        ${
          on
            ? `<div class="list">
          <div class="row v2mo-tr"><div class="lead-ic">${ic("clock")}</div><div class="body"><div class="t">${esc(F.t("monitor.run_time", "Время запуска"))}</div><div class="s">${esc(F.t("monitor.around_specified_time", "Около указанного времени"))}</div></div><div class="tail"><input class="v2mo-time"
            type="time" value="${mon.time}" aria-label="${esc(F.t("monitor.run_time", "Время запуска"))}" data-v2mo-time></div></div>
          ${
            mon.mode === "weekly"
              ? `<div class="row v2mo-days"><div class="lead-ic">${ic("v2-cal")}</div><div class="body"><div class="t">${esc(F.t("monitor.days_week", "Дни недели"))}</div><div class="v2mo-dg">${DAYS()
                  .map(
                    (d, i) => `<button class="chip ${mon.days.has(i + 1) ? "on" : ""}"
            data-act="v2mo-day:${i + 1}"
            aria-pressed="${mon.days.has(i + 1)}">${d}</button>`,
                  )
                  .join("")}</div></div></div>`
              : ""
          }
          <div class="row v2mo-prof"><div class="lead-ic">${ic("shield")}</div><div class="body"><div class="t">${esc(F.t("monitor.repeat_scan_profile", "Профиль повторного скана"))}</div><div class="s">${mon.profile === "std" ? F.t("monitor.standard_downloads_documents", "Стандартный: скачивание документов и DNS целей, без активной фазы.") : F.t("monitor.passive_never_contacts_target", "Пассивный: к цели не обращается.")} ${esc(F.t("monitor.active_modules_brute_force_ports", "Активные модули (перебор, порты, AXFR): только вручную."))}</div>
            <div class="seg v2-segg" role="radiogroup" aria-label="${esc(F.t("monitor.repeat_scan_profile", "Профиль повторного скана"))}">${[
              ["passive", F.t("launch.profile_passive", "Пассивный")],
              ["std", F.t("launch.profile_std", "Стандартный")],
            ]
              .map(
                ([k, l]) =>
                  `<button class="${(mon.profile || "passive") === k ? "on" : ""}"
                    role="radio" aria-checked="${(mon.profile || "passive") === k}"
                    data-act="v2mo-prof:${k}">${l}</button>`,
              )
              .join("")}</div></div></div>
          <div class="row tap"
            data-act="v2mo-t:wifi"><div class="lead-ic">${ic("net")}</div><div class="body"><div class="t">${esc(F.t("monitor.wi_fi_only", "Только по Wi-Fi"))}</div></div><div class="tail">${ui.toggle(mon.wifi, "v2mo-t:wifi", `aria-label="${esc(F.t("monitor.wi_fi_only", "Только по Wi-Fi"))}"`)}</div></div>
          <div class="row tap"
            data-act="v2mo-t:charge"><div class="lead-ic">${ic("battery")}</div><div class="body"><div class="t">${esc(F.t("monitor.only_while_charging", "Только на зарядке"))}</div></div><div class="tail">${ui.toggle(mon.charge, "v2mo-t:charge", `aria-label="${esc(F.t("monitor.only_while_charging", "Только на зарядке"))}"`)}</div></div>
        </div>
        <div class="banner warn v2mo-note">${ic("alert")}<div>${esc(F.t("monitor.android_may_shift_run_time_15", "Android может сдвинуть время запуска на 15 минут и больше в режиме энергосбережения. Чтобы скан не откладывался, разрешите работу в фоне в"))} <a data-act="go:/settings/battery">${esc(F.t("monitor.battery_settings", "настройках батареи"))}</a>.</div></div>
        <div class="banner info v2mo-how">${ic("info")}<div><b>${esc(F.t("monitor.how_repeat_scan_runs", "Как идёт повторный скан."))}</b> ${esc(F.t("monitor.workmanager_runs_scan_schedule", "WorkManager запускает скан по расписанию даже без открытого окна (бюджет ≤ 8 мин; браузерные дорки в фоне пропускаются как «Фоновый режим», а при превышении лимита сохраняется контрольная точка). Если открыть приложение во время фонового скана, оно подключится к текущему прогрессу; при сбое или отключённом фоне придёт напоминание «Пора пересканировать проект»."))}</div></div>`
            : ""
        }
        ${ui.secH(F.t("monitor.notifications_alerts", "Уведомления и алерты"))}
        <div class="list">
          <div class="row tap" data-act="v2mo-al-master"><div class="lead-ic" style="color:var(--accent)">${ic("v2-bell")}</div><div class="body"><div class="t">${esc(F.t("monitor.event_alerts_after_scan", "Событийные алерты после скана"))}</div><div class="s">${esc(F.t("monitor.comparison_previous_scan", "Сравнение со снимком прошлого скана + тренд риска"))}</div></div><div class="tail">${ui.toggle(!!acfg.enabled, "v2mo-al-master", `aria-label="${esc(F.t("monitor.event_alerts", "Событийные алерты"))}"`)}</div></div>
          <div class="row tap" data-act="v2mo-t:tg"><div class="lead-ic"
            style="color:var(--accent)">${ic("v2-tg")}</div><div class="body"><div class="t">${esc(F.t("monitor.telegram_bot", "Telegram-бот"))}</div><div class="s">${tgKey.status === "ok" ? `${esc(F.t("monitor.key_keyvault", "Ключ в KeyVault:"))} ${esc(tgKey.mask)}` : F.t("monitor.token_not_set", "Токен не задан")} · ${tg.ready ? F.t("monitor.ready", "готов") : F.t("monitor.requires_token_chat_id", "требует токен и chat_id")}</div></div><div class="tail">${ui.toggle(!!tg.enabled, "v2mo-t:tg", `aria-label="${esc(F.t("monitor.telegram_bot", "Telegram-бот"))}"`)}</div></div>
          ${
            mon.tg || tg.enabled
              ? `<div class="v2mo-f"><label class="flabel"
                for="v2mo-tok">${esc(F.t("monitor.bot_token_stored_keyvault", "Токен бота (сохраняется в KeyVault)"))}</label><div class="field">${ic("key")}<input id="v2mo-tok"${moErrAttr("tok")}
                placeholder="${tgKey.status === "ok" ? esc(tgKey.mask) + F.t("monitor.leave_empty_keep_unchanged", " (оставьте пустым, чтобы не менять)") : "123456:ABC…"}" type="password"
                autocomplete="off"><button class="ib" data-act="v2mo-eye:v2mo-tok"
                aria-label="${esc(F.t("monitor.show_token", "Показать токен"))}">${ic("eye")}</button></div>
            ${moErr("tok")}
            <label class="flabel"
              for="v2mo-chat">${esc(F.t("monitor.chat_id", "ID чата"))}</label><div class="field">${ic("hash")}<input id="v2mo-chat"
              value="${esc(tg.chat_id || "")}" placeholder="-1001987654321" inputmode="text" autocomplete="off"${moErrAttr("chat")}></div>
            ${moErr("chat")}
            <div class="v2mo-kvrow">
              <button class="btn sm tonal" data-act="v2mo-save-tg">${ic("check")}${esc(F.t("monitor.save_telegram", "Сохранить"))}</button>
              <button class="btn sm" data-act="v2mo-test:telegram">${ic("v2-send")}${esc(F.t("monitor.test", "Тест"))}</button>
              ${tgKey.status === "ok" ? `<button class="btn sm" data-act="v2mo-delkey:tg_bot" aria-label="${esc(F.t("monitor.delete_token", "Удалить токен"))}">${ic("trash")}</button>` : ""}
            </div>
            <p class="fhint">${esc(F.t("monitor.token_goes_straight_into", "Токен уходит напрямую в защищённое хранилище AndroidKeyStore и никогда не пишется в settings.json."))}</p></div>`
              : ""
          }
          <div class="row tap" data-act="v2mo-t:hook"><div class="lead-ic"
            style="color:var(--info)">${ic("v2-hook")}</div><div class="body"><div class="t">Webhook</div><div class="s">${whKey.status === "ok" ? `${esc(F.t("monitor.url_keyvault", "URL в KeyVault:"))} ${esc(whKey.mask)}` : F.t("monitor.url_not_set", "URL не задан")} · ${esc(wh.kind || "generic")}</div></div><div class="tail">${ui.toggle(!!wh.enabled, "v2mo-t:hook", 'aria-label="Webhook"')}</div></div>
          ${
            mon.hook || wh.enabled
              ? `<div class="v2mo-f"><label class="flabel"
                for="v2mo-url">${esc(F.t("monitor.webhook_url_stored_keyvault", "Webhook URL (сохраняется в KeyVault)"))}</label><div class="field">${ic("link")}<input id="v2mo-url"${moErrAttr("url")}
                placeholder="${whKey.status === "ok" ? esc(whKey.mask) : "https://hooks.example.com/foca"}" type="password" inputmode="url" autocomplete="off"><button class="ib" data-act="v2mo-eye:v2mo-url" aria-label="${esc(F.t("monitor.show_url", "Показать URL"))}">${ic("eye")}</button></div>
            ${moErr("url")}
            <label class="flabel" for="v2mo-whkind">${esc(F.t("monitor.payload_format", "Формат полезной нагрузки"))}</label>
            ${ui.select({
              id: "v2mo-whkind",
              value: wh.kind || "generic",
              title: F.t("monitor.payload_format", "Формат полезной нагрузки"),
              options: WH_KINDS.map(([k, l]) => ({ v: k, t: l })),
            })}
            <div class="v2mo-kvrow">
              <button class="btn sm tonal" data-act="v2mo-save-wh">${ic("check")}${esc(F.t("monitor.save_webhook", "Сохранить"))}</button>
              <button class="btn sm" data-act="v2mo-test:webhook">${ic("v2-send")}${esc(F.t("monitor.test", "Тест"))}</button>
              ${whKey.status === "ok" ? `<button class="btn sm" data-act="v2mo-delkey:webhook" aria-label="${esc(F.t("monitor.delete_url", "Удалить URL"))}">${ic("trash")}</button>` : ""}
            </div></div>`
              : ""
          }
        </div>
        <label class="flabel">${esc(F.t("monitor.minimum_alert_severity", "Минимальная важность алертов"))}</label>
        <div class="seg v2-segg v2mo-what" role="radiogroup" aria-label="${esc(F.t("monitor.minimum_severity", "Минимальная важность"))}">${SEV_NAMES()
          .map(
            ([k, l]) =>
              `<button class="${(acfg.min_severity || "warn") === k ? "on" : ""}" role="radio"
              aria-checked="${(acfg.min_severity || "warn") === k}" data-act="v2mo-sev:${k}">${l}</button>`,
          )
          .join("")}</div>
        ${ui.secH(F.t("monitor.event_monitoring_rules", "Правила событийного мониторинга"), availRules.length)}
        <div class="list">${availRules
          .map(r => {
            const rid = r.id;
            const onRule = rulesObj[rid] !== false;
            return ui.row({
              title: esc(RULE_LABELS()[rid] || rid),
              sub: r.is_diff
                ? F.t("monitor.scan_diff", "Сравнение сканов")
                : F.t("monitor.state_check", "Контроль состояния"),
              act: `v2mo-rule:${rid}`,
              chev: false,
              tail: ui.toggle(onRule, `v2mo-rule:${rid}`, `aria-label="${esc(RULE_LABELS()[rid] || rid)}"`),
            });
          })
          .join("")}</div>
        ${
          acfg.history && acfg.history.length
            ? `${ui.secH(F.t("monitor.alert_log", "Журнал алертов"), acfg.history.length)}<div class="list">${acfg.history
                .slice(0, 10)
                .map(h =>
                  ui.row({
                    lead: ui.leadIcon("v2-bell", "var(--warn)"),
                    title: `${esc(
                      String(h.at || "")
                        .replace("T", " ")
                        .slice(0, 16),
                    )} ${F.tp("monitor.count_alerts", h.count || 0, { count: esc(h.count || 0) }, "· {count} алерт|· {count} алерта|· {count} алертов")}`,
                    sub:
                      (h.deliveries || [])
                        .map(d => `${esc(d.channel)}: ${d.ok ? "OK" : esc(d.error || "err")}`)
                        .join(" · ") || F.t("monitor.local", "локально"),
                  }),
                )
                .join("")}</div>`
            : ""
        }
        ${ui.secH(F.t("monitor.scan_history", "История сканов"), "", `<button class="sec-a" data-act="go:/p/diff">${esc(F.t("monitor.compare", "Сравнить"))}</button>`)}
        <div class="list">${SCANS.slice()
          .reverse()
          .map((s, i, arr) => {
            const prev = arr[i + 1];
            const dd = prev ? s.docs - prev.docs : 0;
            return ui.row({
              lead: ui.leadIcon(
                s.how === F.t("monitor.manual", "Вручную") ? "play" : "history",
                s.how === F.t("monitor.manual", "Вручную") ? "" : "var(--info)",
              ),
              title: esc(s.d),
              sub: `${esc(s.how)} ${F.t("monitor.prof_docs_docs", { prof: esc(s.prof), docs: esc(s.docs) }, "· {prof} · {docs} док.")}`,
              tail: prev
                ? `<span class="pill ${dd ? "ok" : "mute"}">${dd ? "+" + dd : F.t("monitor.no_changes", "без изменений")}</span>`
                : `<span class="pill mute">${esc(F.t("monitor.first", "первый"))}</span>`,
              act: prev ? `v2mo-cmp:${prev.id},${s.id}` : "",
            });
          })
          .join("")}</div>`;
        },
        {
          loading: "cards",
          empty: {
            icon: "history",
            title: F.t("monitor.no_scans_yet", "Сканов пока не было"),
            text: F.t(
              "monitor.monitoring_compares_results",
              "Мониторинг сравнивает результаты повторных сканов. Запустите первый скан.",
            ),
          },
        },
      ),
    mount: page => {
      const pid = (F.db.project || {}).id;
      if (pid && (!state.alertCfg || state.alertPid !== pid)) loadMonitorData(pid);
      const t = page.querySelector("[data-v2mo-time]");
      if (t)
        t.addEventListener("change", () => {
          MON().time = t.value;
          monSave();
          F.render(true);
        });
    },
  });
  function updateAlertCfg(patch) {
    const pid = (F.db.project || {}).id;
    F.api.alert_rules_set(patch, pid).then(
      r => {
        state.alertCfg = r;
        F.render(true);
      },
      e => F.snack(F.t("monitor.save_error", "Ошибка сохранения: ") + (e.message || e)),
    );
  }
  Object.assign(F.actions, {
    "v2mo-mode": k => {
      MON().mode = k;
      monSave();
      F.render(true);
    },
    "v2mo-day": d => {
      const s = MON().days;
      d = +d;
      s.has(d) ? s.size > 1 && s.delete(d) : s.add(d);
      monSave();
      F.render(true);
    },
    "v2mo-t": (k, el, e) => {
      e && e.stopPropagation && e.stopPropagation();
      MON()[k] = !MON()[k];
      monSave();
      if (k === "tg" || k === "hook") {
        const curCfg = state.alertCfg || (F.db.settings || {}).alerts || {};
        const curOn =
          k === "tg"
            ? !!(curCfg.telegram && curCfg.telegram.enabled)
            : !!(curCfg.webhook && curCfg.webhook.enabled);
        updateAlertCfg(k === "tg" ? { telegram: { enabled: !curOn } } : { webhook: { enabled: !curOn } });
      }
      F.render(true);
    },
    "v2mo-al-master": (_, el, e) => {
      e && e.stopPropagation && e.stopPropagation();
      const cur = state.alertCfg || (F.db.settings || {}).alerts || {};
      updateAlertCfg({ enabled: !cur.enabled });
    },
    "v2mo-sev": k => updateAlertCfg({ min_severity: k }),
    "v2mo-rule": (rid, el, e) => {
      e && e.stopPropagation && e.stopPropagation();
      const cur = (state.alertCfg && state.alertCfg.rules) || {};
      const next = cur[rid] === false;
      updateAlertCfg({ rules: { [rid]: next } });
    },
    "v2mo-save-tg": () => {
      const pid = (F.db.project || {}).id;
      const tokEl = F.$("#v2mo-tok");
      const chatEl = F.$("#v2mo-chat");
      const tok = tokEl ? tokEl.value.trim() : "";
      const chat = chatEl ? chatEl.value.trim() : "";
      if (!showErrors(["tok", "chat"], channelErrors("telegram", { tok, chat }))) {
        // Keep what the user typed across the re-render.
        const t2 = F.$("#v2mo-tok"),
          c2 = F.$("#v2mo-chat");
        if (t2) t2.value = tok;
        if (c2) c2.value = chat;
        return;
      }
      const pKey = tok ? F.api.key_set("tg_bot", tok) : Promise.resolve();
      pKey
        .then(() => F.api.alert_rules_set({ telegram: { enabled: true, chat_id: chat } }, pid))
        .then(
          r => {
            state.alertCfg = r;
            if (tokEl) tokEl.value = "";
            F.snack(F.t("monitor.telegram_saved_keyvault", "Telegram сохранён в KeyVault"));
            F.render(true);
          },
          e => F.snack(F.t("monitor.error", "Ошибка: ") + F.coreMsg(e.message || e, e.message_msg)),
        );
    },
    "v2mo-save-wh": () => {
      const pid = (F.db.project || {}).id;
      const urlEl = F.$("#v2mo-url");
      const kindEl = F.$("#v2mo-whkind");
      const url = urlEl ? urlEl.value.trim() : "";
      const kind = kindEl ? kindEl.value : "generic";
      if (!showErrors(["url"], channelErrors("webhook", { url }))) {
        const u2 = F.$("#v2mo-url");
        if (u2) u2.value = url;
        return;
      }
      const pKey = url ? F.api.key_set("webhook", url) : Promise.resolve();
      pKey
        .then(() => F.api.alert_rules_set({ webhook: { enabled: true, kind } }, pid))
        .then(
          r => {
            state.alertCfg = r;
            if (urlEl) urlEl.value = "";
            F.snack(F.t("monitor.webhook_saved_keyvault", "Webhook сохранён в KeyVault"));
            F.render(true);
          },
          e => F.snack(F.t("monitor.error", "Ошибка: ") + (e.message || e)),
        );
    },
    "v2mo-delkey": svc => {
      F.api.key_delete(svc).then(
        () => {
          loadMonitorData((F.db.project || {}).id);
          F.snack(F.t("monitor.key_deleted_from_keyvault", "Ключ удалён из KeyVault"));
        },
        e => F.snack(F.t("monitor.error", "Ошибка: ") + (e.message || e)),
      );
    },
    "v2mo-what": k => {
      MON().what = k;
      monSave();
      F.render(true);
    },
    "v2mo-prof": k => {
      MON().profile = k === "std" ? "std" : "passive";
      monSave();
      F.render(true);
    },
    // Revealing a typed token/key requires fingerprint confirmation (like secrets in Data).
    "v2mo-eye": id => {
      const i = F.$("#" + id);
      const flip = () => {
        const j = F.$("#" + id);
        if (!j) return;
        j.type = j.type === "password" ? "text" : "password";
        const b = F.page().querySelector(`[data-act="v2mo-eye:${id}"]`);
        if (b) b.innerHTML = ic(j.type === "password" ? "eye" : "eye-off");
      };
      // Nothing typed yet: there is nothing to reveal, so no fingerprint prompt.
      if (i.type === "password" && i.value && F.dataConfirmFinger)
        F.dataConfirmFinger(flip, F.t("monitor.show_value", "показать значение"));
      else flip();
    },
    "v2ai-key": () => {
      if (F.openKeySheet) F.openKeySheet("ai");
      else F.go("/settings/keys");
    },
    "v2mo-test": ch => {
      const pid = (F.db.project || {}).id;
      const channel = ch === "webhook" ? "webhook" : "telegram";
      const cfg = alertCfgNow();
      const stored =
        channel === "telegram" ? { tok: "", chat: ((cfg.telegram || {}).chat_id || "").trim() } : { url: "" };
      const errs = channelErrors(channel, stored);
      if (Object.keys(errs).length) {
        showErrors(channel === "telegram" ? ["tok", "chat"] : ["url"], errs);
        F.snack(
          F.t(
            "monitor.test_save_first",
            { channel: CHANNEL()[channel] },
            "Сначала заполните и сохраните {channel}.",
          ),
        );
        return;
      }
      F.api.alert_test(channel, pid).then(
        r => {
          if (r && r.ok)
            F.snack(
              `${F.t("monitor.channel_test_delivered_http", { channel: CHANNEL()[channel], status: r.status || 200 }, "Тест {channel}: доставлено (HTTP {status})")}`,
            );
          else
            F.snack(
              `${F.t("monitor.channel_error", { channel: CHANNEL()[channel] }, "Ошибка {channel}:")} ${(r && r.error && F.coreMsg(r.error, r.error_msg)) || F.t("data.no_response", "нет ответа")}`,
            );
        },
        e => F.snack(F.t("monitor.test_error", "Ошибка теста: ") + F.coreMsg(e.message || e, e.message_msg)),
      );
    },
    "v2mo-cmp": ab => {
      const [a, b] = ab.split(",").map(Number);
      state.diff = { a, b, f: "all" };
      F.go("/p/diff");
    },
  });

  // --- what changed ---
  // Changes are computed from two scan snapshots: F.sel.diff(a, b).
  const DG = () => [
    ["docs", F.t("app.documents", "Документы"), "doc"],
    ["hosts", F.t("app.hosts", "Хосты"), "server"],
    ["people", F.t("app.people", "Люди"), "users"],
    ["finds", F.t("nav.findings", "Находки"), "bug"],
    ["tech", F.t("data.site_technologies", "Технологии сайта"), "app"],
  ];
  const DK = () => ({
    "+": [F.t("diff.new", "Новые"), "ok", "plus", F.t("diff.appeared", "Появилось")],
    "-": [F.t("diff.gone", "Исчезли"), "mute", "minus", F.t("diff.disappeared", "Пропало")],
    "~": [F.t("diff.changed", "Изменились"), "warn", "v2-diff", F.t("diff.changed_2", "Изменилось")],
  });
  const DIFF = () =>
    (state.diff = state.diff || {
      a: Math.max(0, SCANS.length - 2),
      b: Math.max(0, SCANS.length - 1),
      f: "all",
    });
  const syncV2 = () => {
    if (GPS !== F.db.gps) {
      state.m3c = null;
      state.m3init = false;
      if (state.m3) state.m3.sel = null;
    } // Another project: rebuild the globe.
    GPS = F.db.gps;
    const tl = F.sel.timeline();
    YEARS = tl.years;
    EVENTS = tl.events;
    SCANS = F.db.scans.map((x, i) => ({
      id: i,
      d: F.fmt.dmyhm(x.finished_at),
      how:
        x.trigger === "schedule" ? F.t("diff.scheduled", "По расписанию") : F.t("monitor.manual", "Вручную"),
      get prof() {
        return x.profile;
      },
      docs: x.docs,
      hosts: x.hosts,
      scan: x,
    }));
    if (state.diff && (state.diff.b >= SCANS.length || state.diff.a >= SCANS.length)) state.diff = null;
    if (state.tl && YEARS.length && state.tl.per === "custom" && !YEARS.includes(state.tl.from))
      state.tl = null;
  };
  syncV2();
  F.on("db", syncV2);
  F.route("/p/diff", {
    title: () => F.t("diff.what_changed", "Что изменилось"),
    tab: "overview",
    back: true,
    render: () =>
      F.withStates(
        () => {
          if (SCANS.length < 2)
            return ui.empty({
              icon: "history",
              title: F.t("diff.nothing_compare_yet", "Сравнивать пока нечего"),
              text: SCANS.length
                ? F.t("diff.second_project_scan_needed", "Для сравнения нужен второй скан проекта.")
                : F.t("diff.no_scans_yet", "Сканов ещё не было."),
            });
          const st = DIFF();
          const scanA = SCANS[st.a],
            scanB = SCANS[st.b];
          const diffRes = F.sel.diff(st.a, st.b);
          const items = diffRes.items;
          const n = k => items.filter(c => c.k === k).length;
          const vis = items.filter(c => st.f === "all" || c.k === st.f);
          const pick = (side, s) =>
            `<button class="card v2d-pick"
              data-act="v2d-pick:${side}"><span class="v2d-pl">${side === "a" ? F.t("diff.before", "Было") : F.t("diff.after", "Стало")}</span><b>${esc(s.d.slice(0, 10))}</b><span class="v2d-ps">${esc(s.d.slice(11))} · ${esc(s.how.toLowerCase())}</span>${ic("chev-down", "v2d-pc")}</button>`;
          return `
        <div class="v2d-cq"><div class="v2d-pair">${pick("a", scanA)}<div class="v2d-arr">${ic("chev")}</div>${pick("b", scanB)}</div>
        ${
          diffRes.incomplete
            ? `<div class="banner warn">${ic("alert")}<div><b>${esc(F.t("diff.incomplete_scan_snapshot", "Неполный снимок скана."))}</b> ${F.t("diff.some_sources_did_not_respond_or", { join: diffRes.incomplete_reasons && diffRes.incomplete_reasons.length ? ` (${esc(diffRes.incomplete_reasons.join(", "))})` : "" }, "Часть источников не ответила или сеть ограничена{join}. Исчезновения и исправления скрыты, чтобы не плодить ложные выводы.")}</div></div>`
            : ""
        }
        <div class="v2d-sum">${["+", "-", "~"]
          .map(
            k => `<button class="v2d-s v2d-${DK()[k][1]} ${st.f === k ? "on" : ""}"
          data-act="v2d-f:${k}"
          aria-pressed="${st.f === k}"><span class="v2d-si">${ic(DK()[k][2])}</span><b>${n(k)}</b><span>${DK()[k][0]}</span></button>`,
          )
          .join("")}</div>
        <p class="fhint v2d-hint">${esc(F.t("diff.counts_all_groups", "Счётчики объединяют все разделы ниже: документы, хосты, людей, находки и технологии."))}</p></div>
        ${
          st.f !== "all"
            ? `<div class="v2d-fl"><span>${esc(F.t("diff.shown", "Показаны:"))} ${DK()[st.f][0].toLowerCase()}</span><button class="btn text sm"
          data-act="v2d-f:all">${esc(F.t("diff.show_all", "Показать все"))}</button></div>`
            : ""
        }
        ${
          vis.length
            ? DG()
                .map(([g, l, i]) => {
                  const arr = vis.filter(c => c.g === g);
                  if (!arr.length) return "";
                  return (
                    ui.secH(l, arr.length) +
                    `<div class="list">${arr
                      .sort((x, y) => "+~-".indexOf(x.k) - "+~-".indexOf(y.k))
                      .map(
                        c =>
                          `<div class="row v2d-row v2d-${DK()[c.k][1]}"><div class="v2d-mk"
                          aria-label="${DK()[c.k][3]}">${ic(DK()[c.k][2])}</div><div class="body"><div class="t">${esc(c.t)}</div><div class="s">${esc(c.s)}</div>${c.was ? `<div class="v2d-ch"><s>${esc(c.was)}</s>${ic("chev")}<b>${esc(c.now)}</b></div>` : ""}${c.sev === "crit" && c.k !== "-" ? `<div class="v2d-sev">${ui.sev("crit")}</div>` : ""}</div></div>`,
                      )
                      .join("")}</div>`
                  );
                })
                .join("")
            : ui.empty({
                icon: "check",
                title: F.t("diff.no_changes", "Изменений нет"),
                text: F.t(
                  "diff.results_match_between_selected",
                  "Между выбранными сканами результаты совпадают.",
                ),
              })
        }`;
        },
        {
          loading: "cards",
          empty: {
            icon: "v2-diff",
            title: F.t("diff.nothing_compare", "Нечего сравнивать"),
            text: F.t("diff.at_least_two_finished_project", "Нужно минимум два завершённых скана проекта."),
          },
        },
      ),
  });
  Object.assign(F.actions, {
    "v2d-f": k => {
      const st = DIFF();
      st.f = st.f === k ? "all" : k;
      F.render(true);
    },
    "v2d-pick": side => {
      const st = DIFF();
      F.sheet({
        title: side === "a" ? F.t("diff.before_scan", "Скан «Было»") : F.t("diff.after_scan", "Скан «Стало»"),
        html: SCANS.slice()
          .reverse()
          .map(s => {
            const dis = side === "a" ? s.id >= st.b : s.id <= st.a;
            const on = st[side] === s.id;
            return `<div class="srow ${on ? "on" : ""} ${dis ? "v2d-dis" : ""}"
              ${dis ? 'aria-disabled="true"' : `data-act="v2d-set:${side},${s.id}"`}>${ic(on ? "check" : s.how === F.t("monitor.manual", "Вручную") ? "play" : "history")}<span class="lbl">${esc(s.d)}<small>${esc(s.how)} ${F.t("diff.prof_docs_docs", { prof: esc(s.prof), docs: esc(s.docs) }, "· {prof} · {docs} док.,")} ${plural(s.hosts, F.t("data.host", "хост"), F.t("data.hosts", "хоста"), F.t("data.host_many", "хостов"))}${dis ? (side === "a" ? F.t("diff.later_than_after", " · позже «Стало»") : F.t("diff.earlier_than_before", " · раньше «Было»")) : ""}</small></span></div>`;
          })
          .join(""),
      });
    },
    "v2d-set": v => {
      const [side, id] = v.split(",");
      DIFF()[side] = +id;
      F.closeSheet();
      F.render(true);
    },
  });

  // ================= PLUGINS =================
  const PLUG = () => [
    {
      id: "ct",
      name: "Certificate Transparency",
      ic: "lock",
      ver: "1.4.0",
      author: F.t("plugins.foca_rs_team", "Команда FOCA-rs"),
      signed: true,
      on: true,
      kind: "external",
      size: F.t("plugins.412_kb", "412 КБ"),
      d: F.t(
        "plugins.finds_organizations_subdomains",
        "Ищет поддомены и сертификаты организации в журналах Certificate Transparency. Не обращается к серверам цели.",
      ),
      net: ["crt.sh", "search.censys.io"],
      files: F.t("plugins.writes_results_project_folder", "Запись результатов в папку проекта"),
      set: [
        ["t", F.t("plugins.include_expired_certificates", "Включать просроченные сертификаты"), false],
        ["t", F.t("plugins.search_organization_name_o", "Искать по названию организации (O=)"), true],
        [
          "s",
          F.t("plugins.history_depth", "Глубина истории"),
          [
            F.t("plugins.1_year", "1 год"),
            F.t("timeline.3_years", "3 года"),
            F.t("plugins.full_history", "Вся история"),
          ],
          1,
        ],
      ],
    },
    {
      id: "git",
      name: "Git/SVN Downloader",
      ic: "download",
      ver: "0.9.2",
      author: F.t("plugins.foca_rs_team", "Команда FOCA-rs"),
      signed: true,
      on: true,
      kind: "active",
      size: F.t("plugins.1_1_mb", "1,1 МБ"),
      d: F.t(
        "plugins.checks_git_svn_availability",
        "Проверяет доступность /.git и /.svn на хостах цели и восстанавливает файлы репозитория из открытых объектов.",
      ),
      net: [F.t("plugins.project_scope_hosts_only", "Только хосты из скоупа проекта")],
      files: F.t("plugins.project_folder_up_200_mb_per", "Папка проекта, до 200 МБ на хост"),
      set: [
        ["t", F.t("plugins.only_check_presence_do_not", "Только проверить наличие, не скачивать"), false],
        [
          "s",
          F.t("plugins.per_host_limit", "Лимит на хост"),
          [F.t("plugins.50_mb", "50 МБ"), F.t("plugins.200_mb", "200 МБ"), F.t("plugins.1_gb", "1 ГБ")],
          1,
        ],
      ],
    },
    {
      id: "iis",
      name: "IIS ShortName",
      ic: "server",
      ver: "2.0.0",
      author: F.t("plugins.foca_rs_team", "Команда FOCA-rs"),
      signed: true,
      on: true,
      kind: "active",
      size: F.t("plugins.286_kb", "286 КБ"),
      d: F.t(
        "plugins.uses_8_3_short_name_disclosure",
        "Использует раскрытие коротких имён 8.3 на Microsoft IIS, чтобы восстановить префиксы скрытых файлов и каталогов.",
      ),
      net: [F.t("plugins.scope_hosts_running_microsoft", "Только хосты из скоупа с Microsoft-IIS")],
      files: F.t("plugins.no_file_access", "Нет доступа к файлам"),
      set: [
        [
          "s",
          F.t("plugins.request_rate", "Скорость запросов"),
          [
            F.t("plugins.gentle_2_s", "Бережно, 2/с"),
            F.t("plugins.normal_10_s", "Обычно, 10/с"),
            F.t("plugins.fast_30_s", "Быстро, 30/с"),
          ],
          0,
        ],
        ["t", F.t("plugins.try_options_debug_methods", "Пробовать методы OPTIONS и DEBUG"), false],
      ],
    },
    {
      id: "hibp",
      name: "Have I Been Pwned",
      ic: "key",
      ver: "2.0.1",
      author: F.t("plugins.foca_rs_team_troy_hunt_api", "Команда FOCA-rs · API Troy Hunt"),
      signed: true,
      on: false,
      kind: "external",
      size: F.t("plugins.198_kb", "198 КБ"),
      key: true,
      d: F.t(
        "plugins.checks_found_employee_e_mails",
        "Проверяет найденные e-mail сотрудников по базе известных утечек. Передаёт только адреса.",
      ),
      net: ["haveibeenpwned.com"],
      files: F.t("plugins.no_file_access", "Нет доступа к файлам"),
      set: [
        ["k", F.t("plugins.hibp_api_key", "Ключ API HIBP")],
        ["t", F.t("plugins.include_unverified_breaches", "Включать непроверенные утечки"), false],
      ],
    },
    {
      id: "recon",
      name: "Recon",
      ic: "search",
      ver: "0.6.0",
      author: F.t("plugins.community_recon_rs", "Сообщество · recon-rs"),
      signed: true,
      on: true,
      kind: "external",
      size: F.t("plugins.740_kb", "740 КБ"),
      d: F.t(
        "plugins.passive_subdomain_reconnaissance",
        "Пассивная разведка поддоменов: DNS-агрегаторы, веб-архив, поисковые системы.",
      ),
      net: ["dnsdumpster.com", "api.securitytrails.com", "web.archive.org"],
      files: F.t("plugins.writes_results_project_folder", "Запись результатов в папку проекта"),
      set: [
        ["t", F.t("plugins.use_web_archive", "Использовать веб-архив"), true],
        ["t", F.t("plugins.verify_found_names_via_dns", "Проверять найденные имена через DNS"), true],
      ],
    },
    {
      id: "sqli",
      name: "SQLi",
      ic: "bug",
      ver: "0.3.1-beta",
      author: F.t("plugins.community_s_koval", "Сообщество · s.koval"),
      signed: false,
      on: false,
      kind: "active",
      size: F.t("plugins.2_4_mb", "2,4 МБ"),
      d: F.t(
        "plugins.tries_safe_payloads_time_based",
        "Пробует безопасные пейлоады (time-based, boolean) в параметрах найденных URL. Работает только для целей скоупа в активной фазе (профиль «Полный»).",
      ),
      net: [F.t("plugins.project_scope_hosts_only", "Только хосты из скоупа проекта")],
      files: F.t("plugins.no_file_access", "Нет доступа к файлам"),
      set: [
        [
          "s",
          F.t("plugins.techniques", "Техники"),
          [F.t("plugins.time_based_only", "Только time-based"), "Time + boolean"],
          0,
        ],
        [
          "s",
          F.t("plugins.delay_between_requests", "Задержка между запросами"),
          [F.t("plugins.1_s", "1 с"), F.t("plugins.3_s", "3 с"), F.t("plugins.10_s", "10 с")],
          1,
        ],
      ],
    },
  ];
  // Plugin state lives in settings.plugins (survives reloads): { [id]: { on?, removed?, installed? } }; HIBP
  // is enabled by its key.
  const NUCLEI = () => ({
    id: "nuclei",
    name: "Nuclei Templates Lite",
    ic: "v2-chip",
    ver: "0.2.0",
    author: F.t("plugins.unknown_author", "Неизвестный автор"),
    signed: false,
    on: false,
    kind: "active",
    size: F.t("plugins.3_8_mb", "3,8 МБ"),
    net: [
      F.t("plugins.scope_hosts_active_permission", "Только хосты из скоупа с разрешением «активно»"),
      "raw.githubusercontent.com",
    ],
    files: F.t("plugins.project_folder_read_write", "Папка проекта: чтение и запись"),
    d: F.t("plugins.checks_hosts_nuclei_templates", "Проверка хостов по шаблонам Nuclei."),
    set: [],
  });
  const PST = () => (F.db.settings || {}).plugins || {};
  const hibpKey = () => {
    const k = ((F.db.settings || {}).keys || {}).hibp;
    return !!(k && k.status === "ok");
  };
  const isOn = p => {
    const st = PST()[p.id];
    if (st && "on" in st) return !!st.on && (!p.key || hibpKey());
    return p.key ? hibpKey() : !!p.on;
  };
  const plugList = () =>
    PLUG()
      .concat((PST().nuclei || {}).installed ? [NUCLEI()] : [])
      .filter(p => !(PST()[p.id] || {}).removed);
  const plugSet = (id, patch) => F.api.settings_set({ plugins: { [id]: patch } });
  // Plugin log, derived from project data (hosts, findings, keys); times are relative to the latest scan.
  function plugLog(plugin) {
    const last = F.sel.lastScan();
    if (!last)
      return [
        [
          "-",
          "mute",
          F.t("plugins.not_run_yet_project_has_no_scans", "Ещё не запускался: в проекте не было сканов"),
        ],
      ];
    const t0 = new Date(last.started_at + "Z").getTime();
    const at = m => new Date(t0 + m * 60000).toISOString().slice(11, 19);
    const keys = (F.db.settings || {}).keys || {};
    const fl = F.db.findings;
    if (plugin.id === "ct") {
      const hs = F.db.hosts.filter(h => /crt\.sh/.test(h.source || ""));
      return [
        [
          at(3),
          "ok",
          `${F.t("plugins.crt_sh_n_certificate_logs", { n: plural(F.db.hosts.filter(h => !h.internal).length, F.t("plugins.name", "имя"), F.t("plugins.names", "имени"), F.t("v2.name_many", "имён")) }, "crt.sh: {n} в журналах сертификатов")}`,
        ],
        [
          at(3),
          hs.length ? "ok" : "mute",
          hs.length
            ? `${F.t("plugins.new_subdomains_n_join", { n: hs.length, join: hs.map(h => shortHost(h.name)).join(", ") }, "Новых поддоменов: {n} ({join})")}`
            : F.t("plugins.no_new_subdomains", "Новых поддоменов нет"),
        ],
        [
          at(4),
          keys.censys && keys.censys.status === "ok" ? "ok" : "mute",
          keys.censys && keys.censys.status === "ok"
            ? F.t("plugins.censys_checked", "Censys: проверено")
            : F.t("plugins.censys_api_key_not_set_skipped", "Censys: ключ API не задан, пропущено"),
        ],
      ];
    }
    if (plugin.id === "git") {
      const g = fl.filter(f => /\.git/.test(f.title));
      return g.length
        ? g.map(f => [f.time.slice(11) + ":00", "bad", `${f.host}: /.git/HEAD → 200`])
        : [
            [
              at(20),
              "ok",
              last.active
                ? F.t("plugins.no_exposed_git_or_svn_found", "Открытых /.git и /.svn не найдено")
                : F.t("plugins.skipped_scan_without_active", "Пропущено: скан без активной фазы"),
            ],
          ];
    }
    if (plugin.id === "iis") {
      const g = fl.filter(f => /IIS/.test(f.source || ""));
      return g.length
        ? g.flatMap(f => [
            [f.time.slice(11) + ":00", "warn", `${f.host}${esc(F.t("plugins.vulnerable", ": уязвим"))}`],
            [
              f.time.slice(11) + ":00",
              "ok",
              String(f.evidence || "")
                .split("\n")
                .pop(),
            ],
          ])
        : [
            [
              at(22),
              "mute",
              F.db.hosts.some(h => /IIS/.test(h.tech || ""))
                ? last.active
                  ? F.t("plugins.iis_hosts_not_vulnerable", "Хосты IIS не уязвимы")
                  : F.t("plugins.skipped_scan_without_active", "Пропущено: скан без активной фазы")
                : F.t("plugins.no_microsoft_iis_hosts", "Хостов на Microsoft-IIS нет"),
            ],
          ];
    }
    if (plugin.id === "hibp")
      return !(keys.hibp && keys.hibp.status === "ok")
        ? [["-", "mute", F.t("plugins.not_run_hibp_api_key_required", "Не запускался: нужен ключ API HIBP")]]
        : !isOn(plugin)
          ? [
              [
                "-",
                "mute",
                F.t(
                  "plugins.plugin_disabled_addresses_were",
                  "Плагин выключен: адреса по утечкам не проверялись",
                ),
              ],
            ]
          : [
              [
                at(6),
                "ok",
                `${F.t("plugins.addresses_checked_n_breaches", { n: F.db.emails.filter(e => !e.role).length }, "Проверено адресов: {n}, в утечках:")} ${Object.keys(F.db.leaks || {}).length}`,
              ],
            ];
    if (plugin.id === "recon") {
      const wb = F.sel.docsLive().filter(d => /web\.archive\.org/.test(d.url)).length;
      return [
        [
          at(1),
          "ok",
          `${F.t("plugins.sources_n_n2_available", { n: (last.sources || []).filter(s => s.status === "ok").length, n2: (last.sources || []).length }, "Источники: {n} из {n2} доступны")}`,
        ],
        [
          at(2),
          "ok",
          wb
            ? `web.archive.org: ${plural(wb, F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов"))}`
            : `${esc(F.t("plugins.documents_found", "Документов найдено:"))} ${last.docs}`,
        ],
      ];
    }
    return [["-", "mute", F.t("plugins.not_run_yet", "Ещё не запускался")]];
  }
  const badge = k =>
    F.moduleBadge
      ? F.moduleBadge(k)
      : `<span class="pill ${k === "external" ? "mute" : "bad"}">${ic(k === "external" ? "globe" : "target")}${k === "external" ? F.t("plugins.external_sources_only", "только внешние источники") : F.t("plugins.contacts_target", "обращается к цели")}</span>`;
  const sigPill = p =>
    p.signed
      ? `<span class="pill ok">${ic("check")}${esc(F.t("plugins.signature_verified", "Подпись проверена"))}</span>`
      : `<span class="pill warn">${ic("alert")}${esc(F.t("plugins.unsigned", "Без подписи"))}</span>`;
  const PLUG_IC = p => (p.runtime === "wasm" ? "v2-chip" : p.kind === "source" ? "globe" : "plug");
  const corePlugList = () => state.corePlugins || [];
  function syncCorePlugins() {
    if (!F.api || !F.api.plugins_list) return Promise.resolve([]);
    return F.api.plugins_list().then(
      res => {
        state.corePlugins = (res && res.items) || [];
        return state.corePlugins;
      },
      () => state.corePlugins || [],
    );
  }
  const coreBadge = p =>
    (p.permissions || []).includes("net:scoped")
      ? `<span class="pill warn">${ic("target")}${esc(F.t("plugins.net_scoped_requires_active_mode", "net:scoped · нужен активный режим"))}</span>`
      : (p.permissions || []).includes("net:passive")
        ? `<span class="pill mute">${ic("globe")}net:passive</span>`
        : `<span class="pill ok">${ic("shield")}${esc(F.t("plugins.offline_meta_read", "офлайн · meta:read"))}</span>`;

  F.route("/settings/plugins", {
    title: () => F.t("settings.plugins", "Плагины"),
    sub: () => F.t("menu.settings", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () =>
      F.withStates(
        () => `
      <p class="lead">${esc(F.t("plugins.plugins_run_sandbox_get_only", "Плагины работают в песочнице и получают только те разрешения, которые вы подтвердили."))}</p>
      ${
        corePlugList().length
          ? `${ui.secH(F.t("plugins.core_sandbox_2_0", "Песочница ядра (2.0)"), `${corePlugList().filter(x => x.enabled).length} ${esc(F.t("app.of", "из"))} ${corePlugList().length}`)}
      <div class="list" id="v2p-core-list">${corePlugList()
        .map(
          p => `<div class="row tap v2p-row" data-act="go:/settings/plugin/${p.id}">
            <div class="lead-ic">${ic(PLUG_IC(p))}</div>
            <div class="body"><div class="t">${esc(p.name)}</div><div class="s">v${esc(p.version)} · ${esc(p.runtime.toUpperCase())} · ${esc(p.source === "builtin" ? F.t("plugins.built", "встроенный") : F.t("plugins.user", "пользовательский"))}</div><div class="v2p-tags">${coreBadge(p)}</div></div>
            <div class="tail">${ui.toggle(!!p.enabled, `v2p-core-on:${p.id}`, `aria-label="${esc(p.name)}"`)}</div></div>`,
        )
        .join("")}</div>`
          : ""
      }
      ${ui.secH(F.t("plugins.scanner_modules", "Модули сканера"))}
      <div class="list">${plugList()
        .map(
          p => `<div class="row tap v2p-row"
            data-act="go:/settings/plugin/${p.id}"><div class="lead-ic"
            ${p.kind !== "external" ? 'style="color:var(--bad);background:var(--bad-soft)"' : ""}>${ic(p.ic)}</div>
        <div class="body"><div class="t">${esc(p.name)}</div><div class="s">v${p.ver} · ${esc(p.author)}</div><div class="v2p-tags">${badge(p.kind)}${p.signed ? "" : sigPill(p)}</div></div>
        <div class="tail">${ui.toggle(isOn(p), `v2p-on:${p.id}`, `aria-label="${esc(p.name)}"`)}</div></div>`,
        )
        .join("")}</div>
      <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:12px">
        <button class="btn tonal" style="flex:1 1 auto" data-act="v2p-install">${ic("v2-file")}${F.isDemo ? F.t("plugins.from_file_wasm", "Из файла (.wasm)") : F.t("plugins.from_file", "Из файла")}</button>
        <button class="btn primary" style="flex:1 1 auto" data-act="v2p-install-json">${ic("plug")}${esc(F.t("plugins.manifest_json_toml", "Манифест (JSON/TOML)"))}</button>
      </div>
      <p class="fhint">${esc(F.t("plugins.sandboxed_plugins_limited_memory", "Плагины в песочнице ограничены по памяти (≤ 16 МиБ) и fuel, не имеют прямого доступа к сокетам/ФС и блокируют запросы к цели в пассивном режиме."))}</p>`,
        {
          empty: {
            icon: "plug",
            title: F.t("plugins.no_plugins", "Плагинов нет"),
            text: F.isDemo
              ? F.t("plugins.install_plugin_from_wasm_file", "Установите плагин из файла .wasm.")
              : F.t("plugins.install_plugin_from_manifest", "Установите плагин из файла манифеста."),
            action: `<button class="btn primary"
              data-act="v2p-install">${ic("v2-file")}${esc(F.t("plugins.install_from_file", "Установить из файла"))}</button>`,
          },
        },
      ),
    mount: () => {
      // Re-render only when the list changed: render(true) mounts again, and the demo backend answers
      // synchronously, so an unconditional re-render loops forever.
      const before = JSON.stringify(state.corePlugins || null);
      syncCorePlugins().then(list => {
        if (JSON.stringify(list || null) === before) return;
        if (F.cur && F.cur.path === "/settings/plugins" && F.render) F.render(true);
      });
    },
  });
  // Plugin id or its position in the list (links like /settings/plugin/1).
  const plugBy = id =>
    plugList().find(p => p.id === id) || (/^\d+$/.test(id) ? plugList()[+id - 1] : undefined);
  const corePlugBy = id => corePlugList().find(p => p.id === id);
  F.route("/settings/plugin/:id", {
    title: p => (corePlugBy(p.id) || plugBy(p.id) || {}).name || F.t("plugins.plugin", "Плагин"),
    sub: () => F.t("settings.plugins", "Плагины"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: pr =>
      F.withStates(
        () => {
          const cp = corePlugBy(pr.id);
          if (cp) {
            return `
        <div class="card pad v2p-hero">
          <div class="v2p-hic">${ic(PLUG_IC(cp))}</div>
          <div class="v2p-hb"><b>${esc(cp.name)}</b><span>v${esc(cp.version)} · ${esc(cp.runtime.toUpperCase())}</span><div class="v2p-tags">${coreBadge(cp)}</div></div>
          <div class="v2p-hon">${ui.toggle(!!cp.enabled, `v2p-core-on:${cp.id}`, `aria-label="${esc(F.t("plugins.enabled", "Включён"))}"`)}</div>
        </div>
        <p class="v2p-desc">${esc(cp.description)}</p>
        <div class="kv">
          <div class="kvr"><div class="k">${esc(F.t("plugins.author", "Автор"))}</div><div class="v">${esc(cp.author)}</div></div>
          <div class="kvr"><div class="k">${esc(F.t("plugins.type_runtime", "Тип / Среда"))}</div><div class="v">${esc(cp.kind)} · ${esc(cp.runtime)}</div></div>
          <div class="kvr"><div class="k">${esc(F.t("plugins.permissions", "Разрешения"))}</div><div class="v">${esc((cp.permissions || []).join(", ") || F.t("plugins.none", "нет"))}</div></div>
          <div class="kvr"><div class="k">SHA-256</div><div class="v mono">${esc((cp.sha256 || "").slice(0, 24))}…</div></div>
          ${cp.url_template ? `<div class="kvr"><div class="k">${esc(F.t("plugins.url_template", "URL-шаблон"))}</div><div class="v mono">${esc(cp.url_template)}</div></div>` : ""}
        </div>
        <div style="display:flex;gap:10px;margin-top:12px">
          <button class="btn primary block" data-act="v2p-core-test:${cp.id}">${ic("play")}${esc(F.t("plugins.sandbox_test_passive", "Тест в песочнице (Пассивно)"))}</button>
        </div>
        ${state.corePluginTest && state.corePluginTest.id === cp.id ? `<div class="card pad" style="margin-top:10px"><div class="s"><b>${esc(F.t("plugins.test_result", "Результат теста"))}</b> · ok=${state.corePluginTest.ok} · fuel=${state.corePluginTest.fuel_used}</div>${state.corePluginTest.blocked_reason ? `<p class="fhint">${esc(state.corePluginTest.blocked_reason)}</p>` : ""}${state.corePluginTest.findings && state.corePluginTest.findings.length ? `<div class="s">${state.corePluginTest.findings.map(f => esc(f.title + ": " + f.detail)).join("<br>")}</div>` : ""}</div>` : ""}
        ${cp.builtin ? "" : `<div class="v2p-del"><button class="btn danger hold block" data-hold="v2p-core-del:${cp.id}"><span class="hold-fill"></span>${ic("trash")}${esc(F.t("plugins.delete_plugin_hold", "Удалить плагин: удерживайте"))}</button></div>`}`;
          }
          const plugin = plugBy(pr.id);
          if (!plugin)
            return ui.empty({
              icon: "plug",
              title: F.t("plugins.plugin_not_found", "Плагин не найден"),
              text: F.t("plugins.may_have_been_deleted", "Возможно, он был удалён."),
              action: `<button class="btn tonal" data-act="back">${esc(F.t("app.back", "Назад"))}</button>`,
            });
          return `
        <div class="card pad v2p-hero">
          <div class="v2p-hic ${plugin.kind !== "external" ? "hit" : ""}">${ic(plugin.ic)}</div>
          <div class="v2p-hb"><b>${esc(plugin.name)}</b><span>v${plugin.ver} · ${plugin.size}</span><div class="v2p-tags">${sigPill(plugin)}</div></div>
          <div class="v2p-hon">${ui.toggle(isOn(plugin), `v2p-on:${plugin.id}`, `aria-label="${esc(F.t("plugins.enabled", "Включён"))}"`)}</div>
        </div>
        <p class="v2p-desc">${esc(plugin.d)}</p>
        <div class="kv"><div class="kvr"><div class="k">${esc(F.t("plugins.author", "Автор"))}</div><div class="v">${esc(plugin.author)}</div></div><div class="kvr"><div class="k">${esc(F.t("about.version", "Версия"))}</div><div class="v">${plugin.ver}</div></div><div class="kvr"><div class="k">${esc(F.t("plugins.signature", "Подпись"))}</div><div class="v">${plugin.signed ? F.t("plugins.verified_foca_rs_plugins_2026", "Проверена · ключ FOCA-rs Plugins 2026") : F.t("plugins.missing_author_not_verified", "Отсутствует: автор не подтверждён")}</div></div></div>
        ${plugin.signed ? "" : `<div class="banner warn v2p-gap">${ic("alert")}<div>${esc(F.t("plugins.plugin_not_signed_enable_only_if", "Плагин не подписан. Включайте его только если доверяете автору и проверили исходный код."))}</div></div>`}
        ${ui.secH(F.t("plugins.permissions", "Разрешения"))}
        ${permList(plugin)}
        ${ui.secH(F.t("plugins.plugin_settings", "Настройки плагина"))}
        <div class="list">${plugin.set
          .map(([t, l, a, b], i) =>
            t === "t"
              ? `<div class="row"><div class="body"><div class="t">${esc(l)}</div></div><div class="tail">${ui.toggle(a, "toggle", `aria-label="${esc(l)}"`)}</div></div>`
              : t === "s"
                ? `<div class="row v2p-sel"><div class="body"><label class="t"
                  for="v2p-s${i}">${esc(l)}</label>${ui.select({
                    id: `v2p-s${i}`,
                    value: String(b),
                    title: l,
                    options: a.map((o, j) => ({ v: String(j), t: o })),
                  })}</div></div>`
                : `<div class="row"><div class="lead-ic">${ic("key")}</div><div class="body"><div class="t">${esc(l)}</div><div class="s">${hibpKey() ? `${esc(F.t("plugins.set_api_keys", "Указан в «Ключах API» ·"))} ${esc((((F.db.settings || {}).keys || {}).hibp || {}).mask || "")}` : F.t("plugins.not_set_plugin_will_not_run", "Не указан: без ключа плагин не запустится")}</div></div><div class="tail"><button class="btn sm tonal"
                  data-act="scan-key:hibp">${hibpKey() ? F.t("app.edit", "Изменить") : F.t("plugins.set", "Указать")}</button></div></div>`,
          )
          .join("")}</div>
        ${ui.secH(F.t("plugins.activity_log", "Журнал работы"), F.t("plugins.last_scan", "последний скан"))}
        <div class="card v2p-log">${plugLog(plugin)
          .map(
            ([t, k, m]) =>
              `<div class="v2p-ll"><span class="mono">${t}</span><i class="v2p-lk ${k}"
                aria-hidden="true"></i><span>${esc(m)}</span></div>`,
          )
          .join("")}</div>
        <div class="v2p-del"><button class="btn danger hold block"
          data-hold="v2p-del:${plugin.id}"><span class="hold-fill"></span>${ic("trash")}${esc(F.t("plugins.delete_plugin_hold", "Удалить плагин: удерживайте"))}</button></div>`;
        },
        { loading: "cards" },
      ),
  });
  function permList(p) {
    return `<div class="list v2p-perm">
      ${ui.row({ lead: ui.leadIcon("globe"), title: F.t("data.network", "Сеть"), sub: p.net.map(n => `<span class="v2p-dom">${esc(n)}</span>`).join("") })}
      ${ui.row({ lead: ui.leadIcon("folder"), title: F.t("plugins.files", "Файлы"), sub: esc(p.files) })}
      ${ui.row({ lead: ui.leadIcon(p.kind === "external" ? "shield" : "target", p.kind === "external" ? "var(--ok)" : "var(--bad)"), title: F.t("plugins.interaction_target", "Взаимодействие с целью"), sub: `<span class="v2p-mb">${badge(p.kind)}</span>${p.kind === "active" ? "<br>" + esc(F.t("plugins.requires_confirmed_active_mode", "Требует подтверждённого активного режима")) : ""}` })}
    </div>`;
  }
  Object.assign(F.actions, {
    "v2p-on": (id, el, e) => {
      const plugin = plugBy(id);
      if (!isOn(plugin) && plugin.key && !hibpKey()) {
        F.snack(F.t("plugins.plugin_needs_hibp_api_key", "Плагину нужен ключ API HIBP"), {
          label: F.t("plugins.set", "Указать"),
          action: () => F.actions["scan-key"]("hibp"),
        });
        return;
      }
      const on = !isOn(plugin);
      el.classList.toggle("on", on);
      el.setAttribute("aria-checked", on);
      plugSet(plugin.id, { on }).catch(e => {
        // Saving failed: put the switch back so it shows the stored state.
        el.classList.toggle("on", !on);
        el.setAttribute("aria-checked", !on);
        F.snack(F.t("plugins.could_not_save", "Не удалось сохранить: ") + ((e && e.message) || e));
      });
      if (on && !plugin.signed)
        F.snack(F.t("plugins.unsigned_plugin_enabled", "Включён неподписанный плагин"), {
          action: () => plugSet(plugin.id, { on: false }).then(() => F.render(true)),
        });
      else if (on && plugin.kind === "active")
        F.snack(F.t("plugins.runs_active_phase_full_profile", "Сработает в активной фазе, профиль «Полный»"));
    },
    "v2p-del": id => {
      const p = plugBy(id);
      plugSet(id, { removed: true });
      F.back();
      setTimeout(
        () =>
          F.snack(`${F.t("plugins.plugin_name_deleted", { name: p.name }, "Плагин «{name}» удалён")}`, {
            action: () => plugSet(id, { removed: false }).then(() => F.render(true)),
          }),
        250,
      );
    },
    "v2p-install": () => {
      // Production: pick a JSON/TOML manifest, read it in the WebView and review it in the manifest sheet
      // before plugin_install. The sample .wasm sheet below is demo-only.
      if (!F.isDemo) {
        F.pickTextFile({
          accept: ".json,.toml,application/json,application/toml,text/plain",
          maxBytes: 256 * 1024,
        }).then(
          f => f && F.actions["v2p-install-json"](f.text),
          e =>
            F.snack(
              F.t("plugins.could_not_read_file", "Не удалось прочитать файл: ") + ((e && e.message) || e),
            ),
        );
        return;
      }
      const plugin = NUCLEI();
      F.sheet({
        title: F.t("plugins.plugin_installation", "Установка плагина"),
        html: `
        <div class="v2p-file">${ic("v2-file")}<div><b>nuclei-lite.wasm</b><span>${plugin.size} · SHA-256 9f2c…a41e</span></div></div>
        <div class="banner warn">${ic("alert")}<div><b>${esc(F.t("plugins.no_signature_found", "Подпись не найдена."))}</b> ${esc(F.t("plugins.author_not_verified_plugin_will", "Автор не подтверждён. Плагин получит доступ ниже. Проверьте, что это вас устраивает."))}</div></div>
        <div class="v2p-ph">${esc(F.t("plugins.plugin_requests", "Плагин запрашивает"))}</div>
        ${permList(plugin)}
        <div class="card v2p-cons">${ui.check(false, F.t("plugins.i_trust_author_allow_listed", "Я доверяю автору и разрешаю перечисленный доступ"), "v2p-cons")}</div>`,
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" id="v2p-go" data-act="v2p-go"
          disabled>${esc(F.t("plugins.install", "Установить"))}</button>`,
      });
      state.newPlug = plugin;
    },
    "v2p-cons": (_, el) => {
      el.classList.toggle("on");
      el.setAttribute("aria-checked", el.classList.contains("on"));
      F.$("#v2p-go").disabled = !el.classList.contains("on");
    },
    "v2p-go": () => {
      plugSet("nuclei", { installed: true, removed: false, on: false }).then(() => F.render(true));
      F.closeSheet();
      F.snack(
        F.t(
          "plugins.plugin_installed_disabled_enable",
          "Плагин установлен и выключен, включите, когда понадобится",
        ),
      );
    },
    "v2p-core-on": (id, el) => {
      const cp = corePlugBy(id);
      if (!cp || !F.api.plugin_toggle) return;
      const next = !cp.enabled;
      el.classList.toggle("on", next);
      el.setAttribute("aria-checked", next);
      F.api.plugin_toggle(id, next).then(
        updated => {
          state.corePlugins = corePlugList().map(x => (x.id === id ? updated : x));
          F.snack(
            next
              ? `${F.t("plugins.plugin_name_enabled", { name: updated.name }, "Плагин «{name}» включён")}`
              : `${F.t("plugins.plugin_name_disabled", { name: updated.name }, "Плагин «{name}» выключен")}`,
          );
        },
        e => {
          el.classList.toggle("on", !next);
          el.setAttribute("aria-checked", !next);
          F.snack((e && e.message) || F.t("plugins.plugin_toggle_error", "Ошибка переключения плагина"));
        },
      );
    },
    "v2p-core-test": id => {
      if (!F.api.plugin_run_test) return;
      F.api
        .plugin_run_test({
          id,
          target: "example.ua",
          passive: true,
          sample_body: "EDRPOU 12345678",
        })
        .then(
          res => {
            state.corePluginTest = res;
            F.render(true);
            F.snack(
              res.ok
                ? F.t("plugins.sandbox_test_passed", "Тест песочницы выполнен")
                : F.t(
                    "plugins.request_blocked_sandbox_adr_0009",
                    "Запрос заблокирован песочницей (ADR-0009)",
                  ),
            );
          },
          e => F.snack((e && e.message) || F.t("plugins.sandbox_test_error", "Ошибка теста песочницы")),
        );
    },
    "v2p-core-del": id => {
      if (!F.api.plugin_remove) return;
      F.api.plugin_remove(id).then(
        () => syncCorePlugins().then(() => F.back()),
        e =>
          F.snack(
            (e && e.message) ||
              F.t("plugins.built_plugin_cannot_deleted", "Нельзя удалить встроенный плагин"),
          ),
      );
    },
    "v2p-install-json": text => {
      const sample =
        typeof text === "string" && text
          ? text
          : JSON.stringify(
              {
                id: "custom-leak-tag",
                name: "Custom Marker Scanner",
                version: "1.0.0",
                author: "Auditor",
                description: F.t(
                  "plugins.search_corporate_labels",
                  "Поиск корпоративных меток в документах (meta:read)",
                ),
                kind: "analyzer",
                runtime: "declarative",
                permissions: ["meta:read"],
                declarative: {
                  extract_kind: "meta_pattern",
                  pattern: "CONFIDENTIAL-[0-9]{4}",
                  severity: "medium",
                },
              },
              null,
              2,
            );
      F.sheet({
        title: F.t("plugins.plugin_installation_json_toml", "Установка плагина (JSON/TOML)"),
        html: `<p class="lead">${esc(F.t("plugins.paste_plugin_manifest_access", "Вставьте манифест плагина. Доступ ограничивается песочницей и разрешениями."))}</p><textarea class="inp mono" id="v2p-m-in" rows="8" style="width:100%;font-size:12px">${esc(sample)}</textarea>`,
        footer: `<button class="btn" data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" data-act="v2p-install-go">${esc(F.t("plugins.install", "Установить"))}</button>`,
      });
    },
    "v2p-install-go": () => {
      const ta = F.$("#v2p-m-in");
      if (!ta || !F.api.plugin_install) return;
      F.api.plugin_install(ta.value).then(
        info => {
          F.closeSheet();
          syncCorePlugins().then(() => F.render(true));
          F.snack(
            `${F.t("plugins.plugin_name_installed", { name: info.name }, "Установлен плагин «{name}»")}`,
          );
        },
        e =>
          F.snack(
            (e && e.message) || F.t("plugins.invalid_plugin_manifest", "Некорректный манифест плагина"),
          ),
      );
    },
  });

  // ================= AI SUMMARY =================
  // AI settings live in settings.ai (survive reloads); only cloud APIs with live `/models` discovery.
  const PROV = () => ({
    openai: ["OpenAI", "api.openai.com"],
    anthropic: ["Anthropic (Claude)", "api.anthropic.com"],
    gemini: ["Google Gemini", "generativelanguage.googleapis.com"],
    deepseek: ["DeepSeek", "api.deepseek.com"],
    xai: ["xAI (Grok)", "api.x.ai"],
    mistral: ["Mistral AI", "api.mistral.ai"],
    groq: ["Groq", "api.groq.com"],
    together: ["Together AI", "api.together.xyz"],
    openrouter: ["OpenRouter", "openrouter.ai"],
    custom: [F.t("ai.custom_openai_compatible_api", "Свой OpenAI-совместимый API"), ""],
  });
  // [value, short label, secondary hint]
  const THINKING_OPTS = () => [
    ["auto", F.t("ai.auto", "Авто"), F.t("ai.think_auto_sub", "по умолчанию модели")],
    ["off", F.t("ai.off", "Выключен")],
    ["minimal", F.t("ai.minimal", "Минимальный")],
    ["low", F.t("sev.low", "Низкий")],
    ["medium", F.t("sev.warn", "Средний")],
    ["high", F.t("sev.high", "Высокий")],
    ["xhigh", F.t("ai.very_high", "Очень высокий"), "xhigh"],
    ["max", F.t("ai.maximum", "Максимум")],
  ];
  const fmtCtx = n =>
    n >= 1000000 ? `${(n / 1000000).toFixed(n % 1000000 ? 1 : 0)}M` : `${Math.round(n / 1000)}K`;
  const AI = () => {
    const a = (F.db.settings || {}).ai || {};
    const r = a.redact || {};
    const prov = PROV()[a.provider] ? a.provider : "deepseek";
    return {
      prov,
      model: a.model || "",
      base_url: a.base_url || "",
      thinking: THINKING_OPTS().some(([k]) => k === a.thinking) ? a.thinking : "auto",
      thinking_budget: Number(a.thinking_budget) || 0,
      max_tokens: Number(a.max_tokens) || 0,
      temperature:
        a.temperature === null || a.temperature === undefined || a.temperature === ""
          ? null
          : Number(a.temperature),
      show_thoughts: !!a.show_thoughts,
      secrets: r.secrets !== false,
      pii: r.pii !== false,
      client: r.client !== false,
      evid: !!r.evid,
    };
  };
  const aiSet = patch => {
    const a = AI();
    Object.assign(a, patch);
    F.api
      .settings_set({
        ai: {
          provider: a.prov,
          model: a.model,
          base_url: a.base_url,
          thinking: a.thinking,
          thinking_budget: a.thinking_budget || 0,
          max_tokens: a.max_tokens || 0,
          temperature: a.temperature === null || Number.isNaN(a.temperature) ? null : a.temperature,
          show_thoughts: !!a.show_thoughts,
          redact: { secrets: a.secrets, pii: a.pii, client: a.client, evid: a.evid },
        },
      })
      .then(() => F.render(true));
  };
  const aiHost = a => {
    if (a.prov !== "custom") return (PROV()[a.prov] || PROV().deepseek)[1];
    try {
      return new URL(a.base_url).hostname || "custom API";
    } catch (e) {
      return "custom API";
    }
  };
  const aiShowAll = () => !!state.aiShowAll;
  const aiCacheKey = a =>
    `${a.prov}|${a.prov === "custom" ? a.base_url || "" : ""}|${aiShowAll() ? "all" : "chat"}`;
  const aiModelsMap = () => (state.aiModels = state.aiModels || {});
  const aiDest = () => {
    const a = AI();
    const p = PROV()[a.prov] || PROV().deepseek;
    return {
      name: p[0],
      host: aiHost(a),
      model: a.model || F.t("ai.model_not_selected", "модель не выбрана"),
      ready: !!a.model,
    };
  };
  const fetchAiModels = (refresh = false, quiet = false) => {
    const a = AI();
    const keyMask = (((F.db.settings || {}).keys || {}).ai || {}).mask || "";
    const showAll = aiShowAll();
    const ck = aiCacheKey(a);
    const cache = aiModelsMap();
    if (cache[ck] && cache[ck].loading) return;
    cache[ck] = { ...(cache[ck] || {}), loading: true, mask: keyMask };
    if (!quiet) F.render(true);
    F.api.ai_models_list(a.prov, a.prov === "custom" ? a.base_url : "", refresh, showAll).then(
      r => {
        cache[ck] = {
          loading: false,
          mask: keyMask,
          models: r.models || [],
          source: r.source || "",
          error: r.error || "",
          host: r.host || "",
        };
        if (r.models && r.models.length && (!a.model || (refresh && !r.models.some(m => m.id === a.model)))) {
          if (!quiet) F.snack(`${esc(F.t("ai.models_loaded", "Загружено моделей:"))} ${r.models.length}`);
          aiSet({ model: r.models[0].id });
          return;
        }
        if (!quiet) {
          if (r.error) F.snack(r.error);
          else F.snack(`${esc(F.t("ai.models_loaded", "Загружено моделей:"))} ${(r.models || []).length}`);
        }
        F.render(true);
      },
      e => {
        cache[ck] = { loading: false, models: [], source: "error", error: e.message || String(e) };
        if (!quiet)
          F.snack(F.t("ai.could_not_load_models", "Не удалось загрузить модели: ") + (e.message || e));
        F.render(true);
      },
    );
  };
  F.route("/settings/ai", {
    title: () => F.t("menu.ai", "ИИ-сводка"),
    sub: () => F.t("menu.settings", "Настройки"),
    nav: false,
    back: true,
    actions: [],
    hideMini: true,
    render: () =>
      F.withStates(() => {
        const ai = AI();
        const host = aiHost(ai);
        const keyInfo = ((F.db.settings || {}).keys || {}).ai || {};
        const hasKey = keyInfo.status === "ok";
        const ck = aiCacheKey(ai);
        const entry = aiModelsMap()[ck] || { loading: false, models: [], source: "", error: "" };
        const models = entry.models || [];
        const activeMeta = models.find(m => m.id === ai.model) || null;
        const hasManual = ai.model && !activeMeta;
        const showBudget =
          (ai.prov === "gemini" || ai.prov === "anthropic") &&
          ai.thinking !== "auto" &&
          ai.thinking !== "off";
        const tg = (k, t, s) =>
          `<div class="row tap"
            data-act="v2ai-t:${k}"><div class="body"><div class="t">${t}</div>${s ? `<div class="s">${s}</div>` : ""}</div><div class="tail">${ui.toggle(ai[k], `v2ai-t:${k}`, `aria-label="${t}"`)}</div></div>`;
        const metaPills = [];
        if (activeMeta) {
          if (activeMeta.thinking === true) metaPills.push(`<span class="pill info">Thinking</span>`);
          if (activeMeta.adaptive_thinking) metaPills.push(`<span class="pill ok">Adaptive</span>`);
          if (activeMeta.context_window)
            metaPills.push(`<span class="pill mute">${fmtCtx(activeMeta.context_window)} ctx</span>`);
          if (activeMeta.max_output_tokens)
            metaPills.push(`<span class="pill mute">${fmtCtx(activeMeta.max_output_tokens)} out</span>`);
        }
        return `
        <p class="lead">${esc(F.t("ai.ai_writes_short_summary_risks", "ИИ составляет краткую сводку рисков и рекомендаций по результатам скана через облачный API выбранного провайдера. Список доступных моделей запрашивается напрямую у провайдера."))}</p>
        <label class="flabel" for="v2ai-p">${esc(F.t("ai.provider", "Провайдер"))}</label>${ui.select({
          id: "v2ai-p",
          value: ai.prov,
          title: F.t("ai.provider", "Провайдер"),
          attrs: 'data-v2ai="prov"',
          options: Object.entries(PROV()).map(([k, v]) => ({ v: k, t: v[0], s: v[1] })),
        })}
        ${
          ai.prov === "custom"
            ? `<label class="flabel" for="v2ai-url">${esc(F.t("ai.base_url_openai_compatible", "Base URL (OpenAI-совместимый)"))}</label><div class="field">${ic("globe")}<input id="v2ai-url" type="url" data-v2ai="base_url" value="${esc(ai.base_url)}" placeholder="https://api.example.com/v1" autocomplete="off"></div>`
            : ""
        }
        <label class="flabel"
          for="v2ai-k">${esc(F.t("ai.api_key", "Ключ API"))}</label><div class="field">${ic("key")}<input id="v2ai-k" type="text"
          value="${esc(keyInfo.mask || "")}" placeholder="${esc(F.t("ai.key_not_set", "Ключ не задан"))}"
          autocomplete="off" readonly><button class="ib" data-act="v2ai-key"
          aria-label="${esc(F.t("ai.change_key", "Изменить ключ"))}">${ic("key")}</button></div>
        <div class="v2ai-mrow v2ai-gap">
          <label class="flabel" for="${models.length ? "v2ai-m" : "v2ai-m-in"}">${esc(F.t("ai.model", "Модель"))}</label>
          <button class="btn text sm" data-act="v2ai-models" ${entry.loading ? "disabled" : ""}>${ic(entry.loading ? "spin" : "refresh", entry.loading ? "spin" : "")}${entry.loading ? F.t("common.loading", "Загрузка…") : F.t("ai.refresh_from_api", "Обновить с API")}</button>
        </div>
        ${
          models.length
            ? ui.select({
                id: "v2ai-m",
                value: ai.model,
                title: F.t("ai.model", "Модель"),
                attrs: 'data-v2ai="model"',
                options: [
                  ...(hasManual ? [{ v: ai.model, t: ai.model, s: F.t("ai.manual", "(вручную)") }] : []),
                  ...models.map(m => ({
                    v: m.id,
                    t: m.label && m.label !== m.id ? m.label : m.id,
                    s: m.label && m.label !== m.id ? m.id : "",
                  })),
                ],
              })
            : ""
        }
        ${metaPills.length ? `<div class="chips wrap v2ai-caps">${metaPills.join("")}</div>` : ""}
        <div class="field ${models.length ? "v2ai-mgap" : ""}">${ic("spark")}<input id="v2ai-m-in" type="text"
          data-v2ai="model" value="${esc(ai.model)}" placeholder="${models.length ? F.t("ai.or_enter_model_id_manually", "Или введите ID модели вручную") : F.t("ai.enter_model_id_or_refresh_from", "Введите ID модели или обновите с API")}" autocomplete="off"></div>
        <div class="list v2ai-mgap">
          <div class="row tap" data-act="v2ai-showall"><div class="body"><div class="t">${esc(F.t("ai.show_all_api_models", "Показать все модели API"))}</div><div class="s">${esc(F.t("ai.disable_providers_service_model", "Отключить фильтр служебных моделей провайдера"))}</div></div><div class="tail">${ui.toggle(aiShowAll(), "v2ai-showall", `aria-label="${esc(F.t("ai.show_all_api_models", "Показать все модели API"))}"`)}</div></div>
        </div>
        <div class="fhint">${
          entry.error
            ? esc(entry.error)
            : models.length
              ? `${esc(F.t("ai.available_models_loaded_from", "Загружено доступных моделей с"))} <span class="mono">${esc(entry.host || host)}</span>: ${models.length}.`
              : hasKey
                ? `${esc(F.t("ai.model_list_requested_directly", "Список моделей запрашивается напрямую у"))} <span class="mono">${esc(host)}</span>.`
                : `${esc(F.t("ai.enter_api_key_load_current_model", "Укажите ключ API, чтобы загрузить актуальный список моделей с"))} <span class="mono">${esc(host)}</span>.`
        } ${esc(F.t("ai.key_kept_androids_protected", "Ключ хранится в защищённом хранилище Android."))}</div>
        ${ui.secH(F.t("ai.reasoning_thinking_generation", "Рассуждение (Thinking) и генерация"))}
        <label class="flabel" for="v2ai-th">${esc(F.t("ai.reasoning_level_thinking", "Уровень рассуждения (Thinking / Reasoning effort)"))}</label>
        ${ui.select({
          id: "v2ai-th",
          value: ai.thinking,
          title: F.t("ai.reasoning_level", "Уровень рассуждений"),
          attrs: 'data-v2ai="thinking"',
          options: THINKING_OPTS().map(([k, l, sub]) => ({ v: k, t: l, s: sub || "" })),
        })}
        ${
          showBudget
            ? `<label class="flabel" for="v2ai-tb">${esc(F.t("ai.reasoning_token_budget_optional", "Бюджет токенов рассуждения (опционально)"))}</label><div class="field">${ic("v2-chip")}<input id="v2ai-tb" type="number" min="0" max="65536" step="256" data-v2ai="thinking_budget" value="${ai.thinking_budget || ""}" placeholder="${esc(F.t("ai.auto_gemini_2_5_claude_budget", "Авто (для Gemini 2.5 / Claude budget_tokens)"))}"></div>`
            : ""
        }
        <div class="grid g2 v2ai-mgap">
          <div><label class="flabel" for="v2ai-mt">${esc(F.t("ai.max_tokens", "Макс. токенов"))}</label><div class="field"><input id="v2ai-mt" type="number" min="0" max="65536" step="256" data-v2ai="max_tokens" value="${ai.max_tokens || ""}" placeholder="${esc(F.t("ai.auto", "Авто"))}"></div></div>
          <div><label class="flabel" for="v2ai-tp">${esc(F.t("ai.temperature", "Температура"))}</label><div class="field"><input id="v2ai-tp" type="number" min="0" max="2" step="0.1" data-v2ai="temperature" value="${ai.temperature === null ? "" : ai.temperature}" placeholder="${esc(F.t("ai.default", "По умолч."))}"></div></div>
        </div>
        <div class="list v2ai-mgap">
          ${tg("show_thoughts", F.t("ai.show_reasoning", "Показывать ход рассуждений"), F.t("ai.collapsible_thinking_block", "Разворачиваемый блок Thinking в результате сводки"))}
        </div>
        <div class="fhint">${esc(F.t("ai.auto_mode_only_basic_fields_sent", "В режиме «Авто» передаются только базовые поля. Модель использует свои настройки рассуждения и температуры без риска HTTP 400."))}</div>
        ${ui.secH(F.t("ai.what_strip_before_sending", "Что вырезать перед отправкой"))}
        <div class="list">
          ${tg("secrets", F.t("app.secrets", "Секреты"), F.t("ai.passwords_keys_tokens_connection", "Пароли, ключи, токены, строки подключения → [СЕКРЕТ]"))}
          ${tg("pii", F.t("ai.personal_data", "Персональные данные"), F.t("ai.full_names_e_mails_phones_email", "ФИО, e-mail, телефоны → [ФИО], [EMAIL]"))}
          ${tg("client", F.t("ai.client_name", "Название заказчика"), F.t("ai.organization_domain", "Организация и домен → [КЛИЕНТ]"))}
          ${tg("evid", F.t("ai.send_evidence", "Отправлять доказательства"), F.t("ai.excerpts_server_responses", "Фрагменты ответов серверов и документов"))}
        </div>
        ${!ai.secrets || !ai.pii ? `<div class="banner crit v2ai-gap">${ic("alert")}<div>${esc(F.t("ai.without_secrets_personal_data", "Без фильтра секретов и персональных данных они могут попасть к внешнему провайдеру. Убедитесь, что владелец данных согласен на их передачу."))}</div></div>` : ""}
        ${
          F.db.project
            ? `<button class="btn primary block v2ai-go"
          data-act="go:/p/ai">${ic("spark")}${esc(F.t("ai.go_summary", "Перейти к сводке"))}</button>`
            : `<p class="fhint v2ai-gap">${ic("info")}${esc(F.t("ai.summary_built_per_project_open", "Сводка строится по проекту. Откройте проект, затем «ИИ-сводка»."))}</p>`
        }`;
      }),
    mount: page => {
      page.querySelectorAll("[data-v2ai]").forEach(s =>
        s.addEventListener("change", () => {
          const k = s.dataset.v2ai;
          if (k === "prov") aiSet({ prov: s.value, model: "" });
          else if (k === "base_url") aiSet({ base_url: s.value.trim(), model: "" });
          else if (k === "thinking_budget" || k === "max_tokens")
            aiSet({ [k]: Math.max(0, Math.min(65536, parseInt(s.value, 10) || 0)) });
          else if (k === "temperature") {
            const raw = s.value.trim();
            const num = raw === "" ? null : Math.max(0, Math.min(2, parseFloat(raw)));
            aiSet({ temperature: Number.isNaN(num) ? null : num });
          } else aiSet({ [k]: s.value.trim() });
        }),
      );
      const ai = AI();
      const keyInfo = ((F.db.settings || {}).keys || {}).ai || {};
      const hasKey = keyInfo.status === "ok";
      const keyMask = keyInfo.mask || "";
      const ck = aiCacheKey(ai);
      const entry = aiModelsMap()[ck];
      const canAutoFetch = ai.prov !== "custom" || !!ai.base_url;
      if (
        hasKey &&
        canAutoFetch &&
        (!entry || entry.source === "no_key" || entry.mask !== keyMask) &&
        !(entry && entry.loading)
      )
        fetchAiModels(false, true);
    },
  });
  F.actions["v2ai-t"] = (k, el, e) => {
    e && e.stopPropagation && e.stopPropagation();
    aiSet({ [k]: !AI()[k] });
  };
  F.actions["v2ai-showall"] = (_, el, e) => {
    e && e.stopPropagation && e.stopPropagation();
    state.aiShowAll = !state.aiShowAll;
    const keyInfo = ((F.db.settings || {}).keys || {}).ai || {};
    if (keyInfo.status === "ok") fetchAiModels(false, false);
    else F.render(true);
  };
  F.actions["v2ai-models"] = () => fetchAiModels(true, false);

  // The prompt text is assembled by the core (ai_preview); the UI shows it as is and highlights the
  // [CLIENT]/[SECRET]/… substitutions.
  const PREVIEW = () =>
    esc((AIS().prev || {}).text || "").replace(
      /\[(КЛИЕНТ-ДОМЕН|КЛИЕНТ|ФИО|EMAIL|СЕКРЕТ|IP-ВНУТР)\]/g,
      m => `<mark class="v2ai-r">${m}</mark>`,
    );
  const SUMMARY = () => AIS().sum || "";
  const AIS = () => (state.ais = state.ais || { step: 0, ok: false, out: "", done: false });
  F.route("/p/ai", {
    title: () => F.t("menu.ai", "ИИ-сводка"),
    tab: "reports",
    back: true,
    actions: () => [{ icon: "gear", act: "go:/settings/ai", label: F.t("ai.ai_settings", "Настройки ИИ") }],
    render: () =>
      F.withStates(
        () => {
          const aiState = AIS(),
            dest = aiDest(),
            ai = AI();
          if (aiState.step === 0)
            return `
        <div class="card pad v2ai-hero"><div class="v2ai-hic">${ic("spark")}</div><b>${esc(F.t("ai.client_summary_minute", "Сводка для заказчика за минуту"))}</b><span>${esc(F.t("ai.key_risks_priority", "Ключевые риски и приоритетные рекомендации по результатам скана. Можно вставить в отчёт."))}</span></div>
        ${ui.secH(F.t("ai.what_included", "Что войдёт"))}
        <div class="list">${[
          [
            "bug",
            F.t("nav.findings", "Находки"),
            `${F.sel.counts().findings.open} ${esc(F.t("ai.current_without_false_positives", "актуальных, без ложных и исправленных"))}`,
          ],
          [
            "doc",
            F.t("ai.document_statistics", "Статистика документов"),
            `${plural(F.sel.counts().docs.total, F.t("projects.document", "документ"), F.t("projects.documents", "документа"), F.t("projects.document_many", "документов"))}${esc(F.t("ai.software_paths", ", ПО, пути"))}`,
          ],
          [
            "users",
            F.t("app.people", "Люди"),
            ai.pii ? F.t("ai.anonymized", "обезличенно") : F.t("ai.names_e_mails", "с именами и e-mail"),
          ],
          [
            "server",
            F.t("app.hosts", "Хосты"),
            plural(
              F.sel.counts().hosts.total,
              F.t("data.host", "хост"),
              F.t("data.hosts", "хоста"),
              F.t("data.host_many", "хостов"),
            ),
          ],
        ]
          .map(([i, t, s2]) => ui.row({ lead: ui.leadIcon(i), title: t, sub: s2, tail: ic("check") }))
          .join("")}</div>
        <div class="card pad v2ai-dst">${ic("globe")}<div><b>${esc(dest.name)} · ${esc(dest.model)}</b><span>${F.t("ai.sending_host_thinking_secrets", { host: esc(dest.host), thinking: ai.thinking !== "auto" ? ` · thinking: ${esc(ai.thinking)}` : "" }, "Отправка на {host}{thinking} · секреты")} ${ai.secrets ? F.t("ai.stripped_2", "вырезаются") : F.t("ai.not_stripped", "НЕ вырезаются")}</span></div><button class="btn text sm"
          data-act="go:/settings/ai">${esc(F.t("app.edit", "Изменить"))}</button></div>
        ${dest.ready ? "" : `<p class="fhint err">${esc(F.t("ai.pick_model_first", "Модель не выбрана: выберите её в настройках ИИ, иначе провайдер отклонит запрос."))}</p>`}
        <button class="btn primary block v2ai-go"
          data-act="v2ai-step:1">${ic("spark")}${esc(F.t("ai.generate", "Сформировать сводку"))}</button>`;
          if (aiState.step === 1) {
            const txt = PREVIEW();
            const marks = (txt.match(/<mark/g) || []).length;
            const tok = (aiState.prev || {}).tokens || 0;
            const cnt = k => (txt.match(new RegExp(`\\[${k}`, "g")) || []).length;
            return `
          <div class="v2ai-steps"><span class="on">${esc(F.t("ai.1_preview", "1 · Предпросмотр"))}</span><span>${esc(F.t("ai.2_summary", "2 · Сводка"))}</span></div>
          <div class="card pad v2ai-dst">${ic("v2-send")}<div><b>${esc(F.t("ai.to", "Куда:"))} ${esc(dest.name)}</b><span class="mono">${esc(dest.host)} · ${esc(dest.model)}${ai.thinking !== "auto" ? ` · thinking:${esc(ai.thinking)}` : ""}</span></div></div>
          <div class="grid g3 v2ai-st">
            <div class="card stat"><div class="k">${esc(F.t("ai.size", "Объём"))}</div><div class="v">≈${fmt(tok)}</div><div class="d">${esc(F.t("ai.tokens", "токенов"))}</div></div>
            <div class="card stat"><div class="k">${esc(F.t("ai.substitutions", "Замен"))}</div><div class="v">${marks}</div><div class="d">${esc(F.t("ai.stripped", "вырезано"))}</div></div>
            <div class="card stat"><div class="k">${esc(F.t("ai.cost", "Стоимость"))}</div><div class="v">&lt;1</div><div class="d">${esc(F.t("ai.cent", "цента"))}</div></div>
          </div>
          <div class="chips wrap v2ai-rc">${[
            ["СЕКРЕТ", F.t("ai.secrets", "секреты")],
            ["EMAIL", "e-mail"],
            ["ФИО", F.t("ai.full_names", "ФИО")],
            ["КЛИЕНТ", F.t("ai.client", "заказчик")],
            ["IP-ВНУТР", F.t("ai.internal_ip", "внутр. IP")],
          ]
            .map(([k, l]) =>
              cnt(k)
                ? `<span class="pill mute"><mark class="v2ai-r">[${k}]</mark>${cnt(k)} · ${l}</span>`
                : "",
            )
            .join("")}</div>
          ${ui.secH(F.t("ai.will_sent", "Будет отправлено"), F.t("ai.unchanged", "без изменений"))}
          <pre class="card v2ai-pre">${txt}</pre>
          ${!ai.secrets || !ai.pii ? `<div class="banner crit">${ic("alert")}<div>${F.t("ai.secrets_filter_off_check_text", { secrets: !ai.secrets ? F.t("ai.secrets_2", "секретов") : F.t("ai.personal_data_2", "персональных данных") }, "Фильтр {secrets} выключен: проверьте текст выше.")}</div></div>` : ""}
          <div class="card v2ai-cons">${ui.check(aiState.ok, `${esc(F.t("ai.i_have_checked_text_agree_send", "Я проверил текст и согласен отправить его в"))} ${esc(dest.name)}`, "v2ai-ok", F.t("ai.provider_may_keep_requests_up_30", "Провайдер может хранить запросы до 30 дней"))}</div>
          <div class="btnrow v2ai-btns"><button class="btn"
            data-act="v2ai-step:0">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" data-act="v2ai-send"
            ${aiState.ok ? "" : "disabled"}>${ic("v2-send")}${esc(F.t("ai.send", "Отправить"))}</button></div>`;
          }
          const thBlock = aiState.thoughts
            ? `<details class="v2ai-th"><summary>${esc(F.t("ai.reasoning_thinking", "Ход рассуждений (Thinking)"))}${aiState.tokens && aiState.tokens.th ? ` ${F.t("ai.th_tok", { th: fmt(aiState.tokens.th) }, "· {th} ток.")}` : ""}</summary><pre>${esc(aiState.thoughts)}</pre></details>`
            : "";
          return `
        <div class="v2ai-steps"><span class="done">${ic("check")}${esc(F.t("look.preview", "Предпросмотр"))}</span><span class="on">${esc(F.t("ai.2_summary", "2 · Сводка"))}</span></div>
        <div class="card pad v2ai-out ${aiState.done ? "done" : ""}"
          aria-live="polite"><div class="v2ai-oh">${ic(aiState.done ? "spark" : "spin", aiState.done ? "" : "spin")}<span>${aiState.done ? `${esc(F.t("ai.done", "Готово ·"))} ${esc(aiState.sourceBadge || dest.name)}${aiState.modelUsed ? ` · ${esc(aiState.modelUsed)}` : ""}` : `${esc(dest.name)} ${esc(F.t("ai.writing_summary", "пишет сводку…"))}`}</span></div>${thBlock}<div class="v2ai-md"
          id="v2ai-md">${md(aiState.out)}${aiState.done ? "" : '<span class="v2ai-cur"></span>'}</div></div>
        <p class="fhint v2ai-fh">${ic("info")} ${esc(F.t("ai.summary_ai_generated_check_facts", "Сводка сгенерирована ИИ: проверьте факты перед отправкой заказчику. Замены вида [КЛИЕНТ] возвращаются на место только в отчёте."))}</p>
        <div class="btnrow v2ai-btns">${
          aiState.done
            ? `<button class="btn"
          data-act="v2ai-copy">${ic("copy")}${esc(F.t("data.copy", "Копировать"))}</button><button class="btn primary"
          data-act="v2ai-rep">${ic("report")}${esc(F.t("ai.report", "В отчёт"))}</button><button class="btn text"
          data-act="v2ai-step:0">${ic("refresh")}${esc(F.t("ai.again", "Заново"))}</button>`
            : `<button class="btn"
          data-act="v2ai-stop">${ic("stop")}${esc(F.t("ai.stop", "Остановить"))}</button>`
        }</div>`;
        },
        {
          loading: "cards",
          empty: {
            icon: "spark",
            title: F.t("ai.nothing_summarize", "Нечего обобщать"),
            text: F.t(
              "ai.summary_appears_after_first_scan",
              "Сводка появится после первого скана с находками.",
            ),
          },
        },
      ),
    mount: () => {
      const aiState = AIS();
      if (aiState.step === 1 && !aiState.prev) F.actions["v2ai-step"](1);
      if (aiState.step === 2 && !aiState.sum) {
        aiState.step = 0;
        F.render(true);
      }
      if (aiState.step === 2 && !aiState.done && aiState.sum) stream();
      F.onBack(
        aiState.step > 0
          ? () => {
              stopStream();
              aiState.step = aiState.step === 2 ? 0 : 0;
              aiState.ok = false;
              F.render(true);
              F.onBack(null);
              return true;
            }
          : null,
      );
    },
    unmount: () => stopStream(),
  });
  function md(t) {
    const lines = esc(t).split("\n");
    let out = "",
      list = null;
    const inl = s => s.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/\*\*(.*)$/, "<b>$1</b>");
    const close = () => {
      if (list) {
        out += `</${list}>`;
        list = null;
      }
    };
    for (const l of lines) {
      if (l.startsWith("## ")) {
        close();
        out += `<h4>${inl(l.slice(3))}</h4>`;
      } else if (/^\d+\. /.test(l)) {
        if (list !== "ol") {
          close();
          out += "<ol>";
          list = "ol";
        }
        out += `<li>${inl(l.replace(/^\d+\. /, ""))}</li>`;
      } else if (l.startsWith("- ")) {
        if (list !== "ul") {
          close();
          out += "<ul>";
          list = "ul";
        }
        out += `<li>${inl(l.slice(2))}</li>`;
      } else if (l.trim()) {
        close();
        out += `<p>${inl(l)}</p>`;
      }
    }
    close();
    return out;
  }
  let sT = null;
  function stopStream() {
    clearInterval(sT);
    sT = null;
  }
  function stream() {
    stopStream();
    const aiState = AIS();
    sT = setInterval(() => {
      const el = F.$("#v2ai-md");
      if (!el) return stopStream();
      const SUM = SUMMARY();
      const rest = SUM.slice(aiState.out.length);
      const m = rest.match(/^\s*\S+\s?/);
      aiState.out += m ? m[0] : rest;
      if (aiState.out.length >= SUM.length) {
        aiState.done = true;
        stopStream();
        F.render(true);
        return;
      }
      el.innerHTML = md(aiState.out) + '<span class="v2ai-cur"></span>';
    }, 28);
  }
  Object.assign(F.actions, {
    "v2ai-step": n => {
      const aiState = AIS();
      stopStream();
      aiState.ok = false;
      aiState.out = "";
      aiState.done = false;
      if (+n === 1)
        return F.api.ai_preview({ redact: AI() }).then(
          r => {
            aiState.prev = r;
            aiState.step = 1;
            F.render(true);
            F.page().scrollTop = 0;
          },
          e => F.snack(F.t("ai.failed", "Не удалось: ") + e.message),
        );
      aiState.step = +n;
      F.render(true);
      F.page().scrollTop = 0;
    },
    "v2ai-ok": (_, el) => {
      const s = AIS();
      s.ok = !s.ok;
      el.classList.toggle("on", s.ok);
      el.setAttribute("aria-checked", s.ok);
      const b = F.page().querySelector('[data-act="v2ai-send"]');
      if (b) b.disabled = !s.ok;
    },
    "v2ai-send": () => {
      const aiState = AIS();
      const opts = AI();
      F.api
        .ai_summarize((aiState.prev || {}).id, {
          redact: opts,
          thinking: opts.thinking,
          thinking_budget: opts.thinking_budget,
          max_tokens: opts.max_tokens,
          temperature: opts.temperature,
          show_thoughts: opts.show_thoughts,
        })
        .then(
          r => {
            aiState.sum = r.md;
            aiState.thoughts = r.thoughts || "";
            aiState.modelUsed = r.model || "";
            aiState.tokens = { in: r.tokens_in || 0, out: r.tokens_out || 0, th: r.tokens_thoughts || 0 };
            aiState.sourceBadge = r.source_badge || "";
            aiState.step = 2;
            aiState.out = "";
            aiState.done = false;
            F.render(true);
            F.page().scrollTop = 0;
          },
          e => {
            if (e.code === "no_key")
              F.snack(F.t("ai.ai_provider_key_required", "Нужен ключ ИИ-провайдера"), {
                label: F.t("plugins.set", "Указать"),
                action: () => F.actions["v2ai-key"](),
              });
            else if (e.code === "bad_input")
              F.snack(e.message, { label: F.t("ai.choose", "Выбрать"), action: () => F.go("/settings/ai") });
            else if (e.code === "stale_preview") {
              F.snack(F.t("ai.data_changed_preview_updated", "Данные изменились: предпросмотр обновлён"));
              F.actions["v2ai-step"](1);
            } else F.snack(F.t("ai.failed", "Не удалось: ") + e.message);
          },
        );
    },
    "v2ai-stop": () => {
      const s = AIS();
      stopStream();
      s.done = true;
      F.render(true);
      F.snack(F.t("ai.generation_stopped", "Генерация остановлена"));
    },
    "v2ai-copy": () => F.actions.copy(SUMMARY().replace(/\*\*/g, "").replace(/## /g, "")),
    "v2ai-rep": () =>
      F.snack(F.t("ai.summary_added_report_as_summary", "Сводка добавлена в отчёт как раздел «Резюме»"), {
        label: F.t("common.open", "Открыть"),
        action: () => F.go("/p/reports"),
      }),
  });

  // ================= WELCOME =================
  const WEL = () => (state.wel = state.wel || { i: 0, ok: false });
  const ILL = () => ({
    1: `<svg viewBox="0 0 240 180" class="v2w-ill" aria-hidden="true">
      <circle cx="120" cy="90" r="70" class="v2w-ring"/><circle cx="120" cy="90" r="44" class="v2w-ring d"/>
      <line x1="120" y1="90" x2="54" y2="52" class="v2w-ln"/><line x1="120" y1="90" x2="188" y2="56"
        class="v2w-ln"/><line x1="120" y1="90" x2="62" y2="138" class="v2w-ln"/><line x1="120" y1="90"
        x2="182" y2="134" class="v2w-ln"/>
      <g class="v2w-node v2-t-doc" transform="translate(54 52)"><path d="M-12 -15H5L12 -8V15H-12Z"
        class="v2w-sh"/><use href="#i-doc" x="-8" y="-8" width="16" height="16"/></g>
      <g class="v2w-node v2-t-person" transform="translate(188 56)"><circle r="15"
        class="v2w-sh"/><use href="#i-user" x="-8" y="-8" width="16" height="16"/></g>
      <g class="v2w-node v2-t-host" transform="translate(62 138)"><path d="M0 -17L17 0L0 17L-17 0Z"
        class="v2w-sh"/><use href="#i-server" x="-8" y="-8" width="16" height="16"/></g>
      <g class="v2w-node v2-t-software"
        transform="translate(182 134)"><polygon points="13,7.5 0,15 -13,7.5 -13,-7.5 0,-15 13,-7.5"
        class="v2w-sh"/><use href="#i-key" x="-8" y="-8" width="16" height="16"/></g>
      <image href="icon.png" x="92" y="62" width="56" height="56" clip-path="inset(0 round 14px)"/></svg>`,
    2: `<svg viewBox="0 0 240 180" class="v2w-ill" aria-hidden="true">
      <rect x="146" y="20" width="88" height="142" rx="16" class="v2w-scope"/><text x="190" y="40"
        class="v2w-tx">${esc(F.t("ai.scope", "скоуп"))}</text>
      <g class="v2w-node v2-t-host" transform="translate(190 120)"><path d="M0 -20L20 0L0 20L-20 0Z"
        class="v2w-sh"/><use href="#i-server" x="-9" y="-9" width="18" height="18"/></g>
      <g class="v2w-pas" transform="translate(32 54)"><circle r="22"
        class="v2w-sh"/><use href="#i-globe" x="-10" y="-10" width="20" height="20"/></g>
      <g class="v2w-src" transform="translate(108 54)"><rect x="-18" y="-15" width="36" height="30"
        rx="8" class="v2w-sh"/><use href="#i-search" x="-8" y="-8" width="16" height="16"/></g>
      <path d="M58 54 H84" class="v2w-arr pas"/><path d="M80 49 L86 54 L80 59" class="v2w-arr pas s"/>
      <text x="70" y="90" class="v2w-tx s">${esc(F.t("ai.external_sources", "внешние источники"))}</text>
      <g class="v2w-act" transform="translate(32 120)"><circle r="22"
        class="v2w-sh"/><use href="#i-target" x="-10" y="-10" width="20" height="20"/></g>
      <path d="M58 120 H160" class="v2w-arr act"/><path d="M154 114 L162 120 L154 126"
        class="v2w-arr act"/></svg>`,
    3: `<svg viewBox="0 0 240 180" class="v2w-ill" aria-hidden="true">
      <rect x="40" y="26" width="92" height="120" rx="8"
        class="v2w-doc"/><path d="M54 50h64M54 64h64M54 78h44M54 120h30"
        class="v2w-dl"/><path d="M92 120c6-10 10 4 16-4s8 2 12-2" class="v2w-sig"/>
      <path d="M170 34l44 16v34c0 30-20 48-44 58-24-10-44-28-44-58V50z"
        class="v2w-shd"/><path d="M152 88l13 13 24-26" class="v2w-chk"/></svg>`,
  });
  const SLIDES = () => [
    {
      t: F.t("welcome.open_source_intelligence", "Разведка по открытым данным"),
      d: F.t(
        "welcome.foca_rs_finds_organizations",
        "FOCA-rs находит документы организации, извлекает метаданные и строит картину: люди, компьютеры, серверы, ПО и утечки секретов.",
      ),
      pts: [
        ["doc", F.t("welcome.documents_metadata", "Документы и метаданные")],
        ["users", F.t("welcome.people_logins_e_mails", "Люди, логины и e-mail")],
        ["bug", F.t("welcome.findings_client_report", "Находки и отчёт для заказчика")],
      ],
    },
    {
      t: F.t("welcome.passive_active_modes", "Пассивный и активный режимы"),
      d: F.t(
        "welcome.passive_mode_uses_only_external",
        "Пассивный режим использует только внешние источники и не касается серверов цели. Активный: обращается к ним напрямую и работает только внутри скоупа проекта.",
      ),
      pts: [
        ["globe", F.t("welcome.passive_search_engines_ct_logs", "Пассивный: поисковики, CT-журналы, архивы")],
        ["target", F.t("welcome.active_requests_scope_hosts", "Активный: запросы к хостам из скоупа")],
        ["target", F.t("welcome.scope_authorization_set_project", "Скоуп и разрешение задаются в проекте")],
      ],
    },
    {
      t: F.t("welcome.only_owners_permission", "Только с разрешения владельца"),
      d: F.t(
        "welcome.testing_other_peoples_systems",
        "Тестирование чужих систем без письменного согласия владельца незаконно. Вы отвечаете за то, как используете приложение.",
      ),
    },
  ];
  F.route("/welcome", {
    topbar: false,
    title: () => F.t("welcome.welcome", "Добро пожаловать"),
    sub: "FOCA-rs",
    nav: false,
    back: false,
    actions: [],
    hideMini: true,
    render: () => {
      const wel = WEL();
      return `<div class="v2w">
        <div class="v2w-vp" id="v2w-vp"><div class="v2w-track" id="v2w-track"
          style="transform:translateX(${-wel.i * 100}%)">
          ${SLIDES()
            .map(
              (s, i) => `<section class="v2w-sl" aria-roledescription="${esc(F.t("welcome.slide", "слайд"))}"
              aria-label="${F.t("welcome.i_3", { i: i + 1 }, "{i} из 3")}" ${i === wel.i ? "" : 'aria-hidden="true"'}>
            <div class="v2w-art ${i === 2 ? "warn" : ""}">${ILL()[i + 1]}</div>
            <h2>${s.t}</h2><p>${s.d}</p>
            ${
              s.pts
                ? `<div class="v2w-pts">${s.pts.map(([i2, t]) => `<div>${ic(i2)}<span>${t}</span></div>`).join("")}</div>`
                : `
              <div class="v2w-pin"><div class="v2w-pinh">${ic("lock")}<span><b>${esc(F.t("welcome.protect_projects_pin", "Защитите проекты PIN-кодом"))}</b><small>${esc(F.t("welcome.project_data_encrypted_pin", "Данные проектов зашифрованы, PIN нужен при запуске"))}</small></span></div>
              <div class="btnrow"><button class="btn tonal" data-act="v2w-pin">${ic("lock")}${esc(F.t("welcome.set_pin", "Задать PIN"))}</button></div>
              <p class="fhint">${esc(F.t("welcome.pin_later", "PIN можно задать и позже: Настройки › Безопасность."))}</p></div>`
            }
          </section>`,
            )
            .join("")}
        </div></div>
        <div class="v2w-foot">
          <div class="v2w-side"><button class="btn text" data-act="v2w-go:2" ${wel.i === 2 ? "hidden" : ""}>${esc(F.t("welcome.skip", "Пропустить"))}</button></div>
          <div class="v2w-dots" role="tablist"
            aria-label="${esc(F.t("welcome.slides", "Слайды"))}">${SLIDES()
              .map(
                (_, i) => `<button class="${i === wel.i ? "on" : ""}" role="tab"
            aria-selected="${i === wel.i}" aria-label="${F.t("welcome.slide_i", { i: i + 1 }, "Слайд {i}")}"
            data-act="v2w-go:${i}"></button>`,
              )
              .join("")}</div>
          <div class="v2w-side end"><button class="btn primary v2w-next" data-act="v2w-go:${Math.min(2, wel.i + 1)}"
            ${wel.i === 2 ? "hidden" : ""}>${esc(F.t("welcome.next", "Далее"))}${ic("chev")}</button><button
            class="btn primary v2w-start" data-act="v2w-done" ${wel.i === 2 ? "" : "hidden"}>${esc(F.t("welcome.start", "Начать"))}</button></div>
        </div></div>`;
    },
    mount: page => {
      page.classList.add("v2w-page");
      const vp = page.querySelector("#v2w-vp"),
        tr = page.querySelector("#v2w-track");
      let x0 = null,
        y0 = 0,
        dx = 0,
        hor = null,
        W = vp.clientWidth;
      vp.addEventListener("pointerdown", e => {
        if (e.target.closest("button,.checkrow")) return;
        x0 = e.clientX;
        y0 = e.clientY;
        dx = 0;
        hor = null;
        W = vp.clientWidth;
      });
      vp.addEventListener("pointermove", e => {
        if (x0 == null) return;
        const ddx = e.clientX - x0,
          ddy = e.clientY - y0;
        if (hor == null && Math.hypot(ddx, ddy) > 10) {
          hor = Math.abs(ddx) > Math.abs(ddy) * 1.2;
          if (hor) {
            tr.classList.add("drag");
            try {
              vp.setPointerCapture(e.pointerId);
            } catch (x) {}
          }
        }
        if (!hor) return;
        const wel = WEL();
        dx = ddx;
        if ((wel.i === 0 && dx > 0) || (wel.i === 2 && dx < 0)) dx *= 0.3;
        tr.style.transform = `translateX(${-wel.i * W + dx}px)`;
      });
      const end = () => {
        if (x0 == null) return;
        x0 = null;
        tr.classList.remove("drag");
        if (!hor) return;
        const w = WEL();
        const th = Math.min(80, W * 0.2);
        let i = w.i;
        if (dx < -th) i++;
        if (dx > th) i--;
        welGo(Math.max(0, Math.min(2, i)));
      };
      vp.addEventListener("pointerup", end);
      vp.addEventListener("pointercancel", end);
    },
  });
  function welGo(i) {
    const wel = WEL();
    wel.i = i;
    const pg = F.page();
    const tr = pg.querySelector("#v2w-track");
    tr.style.transform = `translateX(${-i * 100}%)`;
    pg.querySelectorAll(".v2w-sl").forEach((s, k) =>
      k === i ? s.removeAttribute("aria-hidden") : s.setAttribute("aria-hidden", "true"),
    );
    pg.querySelectorAll(".v2w-dots button").forEach((b, k) => {
      b.classList.toggle("on", k === i);
      b.setAttribute("aria-selected", k === i);
    });
    pg.querySelector(".v2w-foot .btn.text").hidden = i === 2;
    const nx = pg.querySelector(".v2w-next");
    nx.hidden = i === 2;
    nx.dataset.act = `v2w-go:${Math.min(2, i + 1)}`;
    pg.querySelector(".v2w-start").hidden = i !== 2;
  }
  Object.assign(F.actions, {
    "v2w-go": i => welGo(+i),
    "v2w-done": () => {
      try {
        localStorage.setItem("foca-welcomed", "1");
      } catch (e) {}
      F.reset(["/projects"]);
    },
    "v2w-pin": () => {
      let pin = "",
        first = null;
      const draw = sh => {
        sh.querySelector(".v2w-pdots").innerHTML = [0, 1, 2, 3]
          .map(i => `<i class="${i < pin.length ? "on" : ""}"></i>`)
          .join("");
        sh.querySelector(".v2w-ph").textContent = first
          ? F.t("welcome.repeat_pin", "Повторите PIN")
          : F.t("welcome.choose_4_digit_pin", "Придумайте PIN из 4 цифр");
      };
      F.sheet({
        title: F.t("welcome.pin_code", "PIN-код"),
        html: `<p class="v2w-ph"></p><div class="v2w-pdots"
          aria-live="polite"></div><div class="v2w-pad">${[1, 2, 3, 4, 5, 6, 7, 8, 9, "", 0, "x"]
            .map(k =>
              k === ""
                ? "<span></span>"
                : `<button class="v2w-key"
          data-k="${k}"
          aria-label="${k === "x" ? F.t("welcome.erase", "Стереть") : k}">${k === "x" ? ic("back") : k}</button>`,
            )
            .join(
              "",
            )}</div><p class="fhint v2w-pinhint">${esc(F.t("welcome.you_can_enable_fingerprint_login", "Можно включить вход по отпечатку в настройках безопасности."))}</p>`,
        onMount: sh => {
          draw(sh);
          sh.querySelector(".v2w-pad").addEventListener("click", e => {
            const keyEl = e.target.closest(".v2w-key");
            if (!keyEl) return;
            const k = keyEl.dataset.k;
            if (k === "x") pin = pin.slice(0, -1);
            else if (pin.length < 4) pin += k;
            draw(sh);
            if (pin.length === 4)
              setTimeout(() => {
                if (!first) {
                  first = pin;
                  pin = "";
                  draw(sh);
                } else if (first === pin) {
                  F.api.pin_set(pin).then(
                    () => {
                      F.closeSheet();
                      F.snack(F.t("welcome.pin_set", "PIN задан"));
                      F.actions["v2w-done"]();
                    },
                    e => F.snack(F.t("ai.failed", "Не удалось: ") + e.message),
                  );
                } else {
                  first = null;
                  pin = "";
                  draw(sh);
                  sh.querySelector(".v2w-ph").textContent = F.t(
                    "welcome.pins_did_not_match_try_again",
                    "PIN не совпал, попробуйте снова",
                  );
                }
              }, 180);
          });
        },
      });
    },
  });

  // ================= PRE-PUBLICATION CHECK (protective mode) =================
  // Pick your own files → see what would leak (metadata, paths, GPS, revisions, secrets) → save cleaned
  // copies.
  // In demo mode the "device files" are the current project's parsed documents (the app uses the system file
  // picker).
  /** Lead icon colour per leak severity on the pre-publication check. */
  const LEAK_COLOR = { crit: "var(--crit)", high: "var(--bad)", warn: "var(--warn)" };
  const PF = () => (state.pf = state.pf || { step: 0, files: [], cleaned: [] });
  const pfCands = () =>
    F.sel
      .docsLive()
      .filter(d => d.status_code === "analyzed")
      .sort(
        (a, b) =>
          b.findings.filter(k => k !== "eol").length - a.findings.filter(k => k !== "eol").length ||
          a.id - b.id,
      )
      .slice(0, 14);
  function pfLeaks(doc) {
    const out = [];
    const secs = F.db.secrets.filter(s => s.doc === doc.id);
    if (secs.length)
      out.push([
        "crit",
        "key",
        `${esc(F.t("preflight.secrets_text", "Секреты в тексте:"))} ${secs.length}`,
        secs.map(s => s.where).join("; "),
        false,
      ]);
    if (doc.gps)
      out.push([
        "high",
        "pin",
        F.t("preflight.shooting_gps_coordinates", "GPS-координаты съёмки"),
        `${doc.gps.lat}, ${doc.gps.lon} · ${doc.gps.place}`,
        true,
      ]);
    if (doc.revisions && doc.revisions.length)
      out.push([
        "warn",
        "history",
        `${esc(F.t("preflight.tracked_changes_comments", "Исправления и комментарии:"))} ${doc.revisions.length}`,
        doc.revisions
          .map(r => `«${r.text}»`)
          .slice(0, 2)
          .join(", "),
        true,
      ]);
    if (doc.folder && doc.folder !== "-")
      out.push(["warn", "path", F.t("preflight.internal_path", "Внутренний путь"), doc.folder, true]);
    if (doc.printer && doc.printer !== "-")
      out.push(["warn", "printer", F.t("data.printer_2", "Принтер"), doc.printer, true]);
    if (doc.rdp)
      out.push([
        "warn",
        "server",
        F.t("preflight.server_address_user_rdp", "Адрес сервера и пользователь (.rdp)"),
        `${doc.rdp.full_address} · ${doc.rdp.username}`,
        false,
      ]);
    if (doc.lnk)
      out.push([
        "warn",
        "monitor",
        F.t("preflight.pc_name_mac_volume_serial_lnk", "Имя ПК, MAC, серийник тома (.lnk)"),
        `${doc.lnk.machine} · ${doc.lnk.mac}`,
        true,
      ]);
    if (doc.author)
      out.push([
        "low",
        "user",
        F.t("preflight.author_last_modified", "Автор и последний изменивший"),
        [doc.author, doc.last_modified_by].filter((x, i, a) => x && a.indexOf(x) === i).join(", "),
        true,
      ]);
    if (doc.company)
      out.push(["low", "contract", F.t("preflight.organization", "Организация"), doc.company, true]);
    if (doc.software)
      out.push([
        doc.findings.includes("eol") ? "warn" : "low",
        "app",
        doc.findings.includes("eol")
          ? F.t("preflight.unsupported_program", "Программа без поддержки")
          : F.t("preflight.program_version", "Программа и версия"),
        `${doc.sw.name} ${doc.sw.ver}`,
        true,
      ]);
    if (doc.camera) out.push(["low", "camera", F.t("preflight.camera", "Камера"), doc.camera, true]);
    return out;
  }
  const PFS = { crit: 0, high: 1, warn: 2, low: 3 };
  const pfSev = l => (l.length ? l.slice().sort((a, b) => PFS[a[0]] - PFS[b[0]])[0][0] : "ok");
  F.route("/p/preflight", {
    title: () => F.t("preflight.pre_publication_check", "Проверка перед публикацией"),
    sub: () => F.t("preflight.protective_mode", "Защитный режим"),
    back: true,
    nav: false,
    hideMini: true,
    actions: [],
    render: () =>
      F.withStates(
        () => {
          const st = PF();
          const cands = pfCands();
          const files = st.files.map(id => F.sel.entity("doc", id)).filter(Boolean);
          if (st.step === 0 || !files.length)
            return `
        <div class="card pad v2pf-hero"><div class="v2ai-hic">${ic("shield")}</div><b>${esc(F.t("preflight.check_files_before_publishing", "Проверьте файлы до публикации"))}</b><span>${esc(F.t("preflight.before_you_upload_documents_or", "Перед тем как выложить документы или фото на сайт, FOCA-rs покажет, что из них можно извлечь, и сохранит очищенные копии. Файлы не покидают устройство."))}</span></div>
        ${ui.secH(F.t("preflight.what_checked", "Что проверяется"))}
        <div class="list">${[
          ["user", F.t("preflight.author_organization_who_edited", "Автор, организация, кто менял")],
          ["path", F.t("preflight.internal_paths_printers_pc_names", "Внутренние пути, принтеры, имена ПК")],
          ["pin", F.t("preflight.gps_camera_photos", "GPS и камера в фото")],
          ["history", F.t("preflight.tracked_changes_comments_2", "Исправления и комментарии")],
          ["key", F.t("preflight.passwords_keys_text", "Пароли и ключи в тексте")],
        ]
          .map(([i, t]) => ui.row({ lead: ui.leadIcon(i), title: t }))
          .join("")}</div>
        ${
          !F.isDemo
            ? `<button class="btn primary block v2pf-go"
              data-act="v2pf-pick">${ic("folder")}${esc(F.t("preflight.choose_files", "Выбрать файлы"))}</button><p class="fhint">${ic("info")} ${esc(F.t("preflight.system_file_picker_opens_files", "Откроется системный выбор файлов. Файлы копируются в проект как локальные документы и разбираются на устройстве: в сеть ничего не уходит."))}</p>`
            : cands.length
              ? `<button class="btn primary block v2pf-go"
                data-act="v2pf-pick">${ic("folder")}${esc(F.t("preflight.choose_files", "Выбрать файлы"))}</button><p class="fhint">${ic("info")} ${esc(F.t("preflight.demo_current_projects_documents", "Демо: для выбора предлагаются документы текущего проекта; в приложении откроется системный выбор файлов Android."))}</p>`
              : `<div class="card pad v2pf-none">${ic("info")}<span>${esc(F.t("preflight.demo_files_check_taken_from", "В демо файлы для проверки берутся из документов проекта, а в этом проекте разобранных документов пока нет. В приложении здесь откроется системный выбор файлов."))}</span></div>`
        }`;
          const leaks = files.map(d => [d, pfLeaks(d)]);
          // Hygiene grades (hygiene_get): the set summary, a grade per file and the fix steps.
          const hy = F.hyg ? F.hyg.forIds(st.files) : null;
          const rep = id => (hy && hy.docs ? hy.docs.find(r => r.id === id) : null);
          const signed = !!(hy && hy.docs && hy.docs.some(r => r.issues.some(i => i.code === "signed")));
          const risky = leaks.filter(([, l]) => l.some(x => x[0] !== "low")).length;
          const cleaned = new Set(st.cleaned);
          const res = st.res || {};
          // Green "Cleaned" only when no manual items remain (secrets in the text cannot be removed as
          // metadata).
          const manualOf = d => (res[d.id] ? res[d.id].manual.length : pfLeaks(d).filter(x => !x[4]).length);
          const full = files.filter(d => cleaned.has(d.id) && !manualOf(d)).length,
            part = files.filter(d => cleaned.has(d.id) && manualOf(d)).length;
          return `
        <div class="grid g3 v2pf-st">
          <div class="card stat"><div class="k">${esc(F.t("preflight.files", "Файлов"))}</div><div class="v">${files.length}</div><div class="d">${esc(F.t("preflight.selected", "выбрано"))}</div></div>
          <div class="card stat"><div class="k">${esc(F.t("preflight.risks", "С рисками"))}</div><div class="v">${risky}</div><div class="d">${esc(F.t("preflight.besides_author_software", "кроме автора/ПО"))}</div></div>
          <div class="card stat"><div class="k">${esc(F.t("preflight.cleaned_2", "Очищено"))}</div><div class="v">${full}</div><div class="d">${part ? `${F.t("preflight.part_more_partially", { part }, "ещё {part} частично")}` : F.t("preflight.copies", "копий")}</div></div>
        </div>
        ${hy && hy.set ? F.hyg.setHtml(hy.set) : ""}
        ${
          cleaned.size
            ? F.isDemo
              ? `<div class="banner info">${ic("check")}<div>${esc(F.t("preflight.cleaned_copies_saved", "Очищенные копии сохранены в"))} <span class="mono">Download/FOCA-rs/clean/</span>${esc(F.t("preflight.originals_unchanged_secrets_text", ". Оригиналы не изменены. Секреты в тексте автоматически не удаляются, отредактируйте документ."))}</div></div>`
              : `<div class="banner info">${ic("check")}<div>${esc(F.t("preflight.cleaned_copies_ready_apps", "Очищенные копии готовы в приватной папке приложения. Оригиналы не изменены. Секреты в тексте автоматически не удаляются, отредактируйте документ."))}<div class="btnrow"><button class="btn sm tonal"
                data-act="v2pf-save">${ic("download")}${esc(F.t("preflight.save_downloads", "Сохранить в «Загрузки»"))}</button></div></div></div>`
            : ""
        }
        ${ui.secH(F.t("preflight.what_will_leak", "Что утечёт"), "", `<button class="sec-a" data-act="v2pf-pick">${esc(F.t("preflight.change_selection", "Изменить выбор"))}</button>`)}
        ${leaks
          .map(
            ([d, l]) => `<div class="card v2pf-file sev-${pfSev(l)}">
          <div class="v2pf-fh"><span class="ext ${esc(d.ext)}">${esc(d.ext)}</span><b class="v2pf-fn">${esc(d.name)}</b>${rep(d.id) ? F.hyg.gradeBadge(rep(d.id).grade) : ""}${cleaned.has(d.id) ? (manualOf(d) ? `<span class="pill warn">${ic("alert")}${esc(F.t("preflight.partially_cleaned", "Очищен частично"))}</span>` : `<span class="pill ok">${ic("eraser")}${esc(F.t("preflight.cleaned", "Очищен"))}</span>`) : pfSev(l) === "ok" ? `<span class="pill ok">${ic("check")}${esc(F.t("preflight.clean", "Чисто"))}</span>` : ui.sev(pfSev(l))}</div>
          <div class="list v2pf-l">${l.map(([s, i, t, v, auto]) => ui.row({ lead: ui.leadIcon(i, LEAK_COLOR[s] || ""), title: esc(t), sub: `<span class="mono v2pf-v">${esc(v)}</span>${cleaned.has(d.id) ? (auto ? ` · <span class="v2pf-ok">${esc(F.t("preflight.removed", "удалено"))}</span>` : ` · <span class="v2pf-no">${esc(F.t("preflight.manual_action_needed", "нужно вручную"))}</span>`) : ""}`, cls: cleaned.has(d.id) && auto ? "v2pf-done" : "" })).join("") || `<div class="row"><div class="body"><div class="s">${esc(F.t("preflight.no_metadata_found", "Метаданных не найдено"))}</div></div></div>`}</div>
          ${rep(d.id) ? `<div class="v2pf-hy">${F.hyg.stepsHtml(rep(d.id))}</div>` : ""}
          ${cleaned.has(d.id) && manualOf(d) ? `<div class="banner warn v2pf-man">${ic("alert")}<div><b>${esc(F.t("preflight.metadata_cleaned_secret_remains", "Метаданные очищены, в тексте остался секрет, правьте документ."))}</b> ${F.t("preflight.do_not_publish_copy_until_you", { d: manualOf(d) === 1 ? F.t("preflight.it", "его") : F.t("preflight.them", "их") }, "Не публикуйте копию, пока не уберёте {d} вручную.")}</div></div>` : ""}
          ${
            cleaned.has(d.id)
              ? res[d.id] && res[d.id].verify
                ? `<div class="btnrow"><button class="btn tonal"
            data-act="v2pf-ba:${d.id}">${ic("eye")}${esc(F.t("preflight.before_after", "До / После"))}</button></div>`
                : ""
              : `<div class="btnrow"><button class="btn tonal"
            data-act="v2pf-clean:${d.id}">${ic("eraser")}${esc(F.t("preflight.clean_2", "Очистить"))}</button></div>`
          }
        </div>`,
          )
          .join("")}
        ${F.hyg && files.some(d => !cleaned.has(d.id)) ? F.hyg.optionsHtml(signed) : ""}
        <div class="foot"><div class="btnrow"><button class="btn"
          data-act="v2pf-reset">${esc(F.t("preflight.check_other_files", "Проверить другие файлы"))}</button><button class="btn primary"
          data-act="v2pf-clean:all"
          ${files.every(d => cleaned.has(d.id)) ? "disabled" : ""}>${ic("eraser")}${esc(F.t("preflight.clean_all", "Очистить все"))}</button></div></div>`;
        },
        {
          loading: "cards",
          empty: {
            icon: "shield",
            title: F.t("preflight.no_files_check", "Нет файлов для проверки"),
            text: F.t(
              "preflight.choose_documents_or_photos_you",
              "Выберите документы или фото, которые собираетесь опубликовать.",
            ),
          },
        },
      ),
    mount: page => {
      if (page.querySelector(".foot")) page.classList.add("no-pb");
    },
  });
  Object.assign(F.actions, {
    "v2pf-pick": () => {
      const st = PF();
      // With the core, real files: system picker (SAF) → copies → doc_import (offline parsing) → check.
      if (!F.isDemo) {
        return F.api
          .platform_pick_files({ multiple: true })
          .then(r => {
            const fl = (r && r.files) || [];
            if (!fl.length) return;
            F.snack(
              `${F.t("preflight.analyzing_n_files", { n: fl.length, files: fl.length === 1 ? F.t("preflight.file", "файла") : F.t("preflight.files_2", "файлов") }, "Разбор {n} {files}…")}`,
            );
            return F.api.doc_import(fl.map(f => f.path)).then(x => {
              Object.assign(st, { step: 1, files: x.ids || [], cleaned: [], res: {} });
              F.render(true);
            });
          })
          .catch(e =>
            F.snack(
              F.t("preflight.could_not_check_files", "Не удалось проверить файлы: ") + (e.message || e),
            ),
          );
      }
      const sel = new Set(
        st.files.length
          ? st.files
          : pfCands()
              .filter(d => d.findings.some(k => k !== "eol"))
              .slice(0, 4)
              .map(d => d.id),
      );
      const draw = sh => {
        sh.querySelector(".sh-b").innerHTML =
          `<p class="lead">${esc(F.t("preflight.select_files_you_going_publish", "Отметьте файлы, которые собираетесь опубликовать."))}</p><div class="list">${pfCands()
            .map(d =>
              ui.check(
                sel.has(d.id),
                `<span class="mono v2pf-cn">${esc(d.name)}</span>`,
                `v2pf-t:${d.id}`,
                `${d.ext.toUpperCase()} ${F.t("preflight.n_kb", { n: d.size }, "· {n} КБ")}`,
              ),
            )
            .join("")}</div>`;
        const okBtn = sh.querySelector("#v2pf-ok");
        okBtn.textContent = `${F.t("preflight.check_n", { n: sel.size }, "Проверить ({n})")}`;
        okBtn.disabled = !sel.size;
      };
      F.sheet({
        title: F.t("preflight.file_selection", "Выбор файлов"),
        html: "",
        footer: `<button class="btn"
          data-act="sheet-close">${esc(F.t("common.cancel", "Отмена"))}</button><button class="btn primary" id="v2pf-ok"
          data-act="v2pf-run">${esc(F.t("preflight.check", "Проверить"))}</button>`,
        onMount: sh => {
          draw(sh);
          F.actions["v2pf-t"] = id => {
            id = +id;
            sel.has(id) ? sel.delete(id) : sel.add(id);
            const y = sh.querySelector(".sh-b").scrollTop;
            draw(sh);
            sh.querySelector(".sh-b").scrollTop = y;
          };
          F.actions["v2pf-run"] = () => {
            Object.assign(st, { step: 1, files: [...sel], cleaned: st.cleaned.filter(i => sel.has(i)) });
            F.closeSheet();
            F.render(true);
          };
        },
      });
    },
    // Cleaning is done by the core (doc_clean): what was removed and what remains to fix manually (a secret
    // in the text).
    "v2pf-clean": id => {
      const st = PF();
      const ids = id === "all" ? st.files.filter(x => !st.cleaned.includes(x)) : [+id];
      F.api.doc_clean(ids, F.hyg ? F.hyg.opts() : undefined).then(
        r => {
          st.res = st.res || {};
          r.cleaned.forEach(c => {
            st.res[c.id] = c;
          });
          st.cleaned = [...new Set(st.cleaned.concat(ids))];
          // Before/after self-check of the clean copies (diff, verdict, signature warning, share).
          // "Clean all" stays on the list (every card gets "До / После"); one file opens the screen at once.
          if (F.hyg && id !== "all" && r.cleaned.some(c => c.verify))
            return F.hyg.showResults(r.cleaned, "/p/preflight");
          F.render(true);
          const man = r.cleaned.filter(c => c.manual.length).length;
          F.snack(
            `${ids.length > 1 ? `${esc(F.t("preflight.copies_cleaned", "Очищено копий:"))} ${ids.length}` : F.t("preflight.cleaned_copy_saved", "Очищенная копия сохранена")}${man ? ` ${esc(F.t("preflight.manually", "· вручную:"))} ${man}` : ""}`,
            {
              action: () => {
                st.cleaned = st.cleaned.filter(x => !ids.includes(x));
                F.render(true);
              },
            },
          );
        },
        e => F.snack(F.t("ai.failed", "Не удалось: ") + e.message),
      );
    },
    "v2pf-ba": id => {
      const c = (PF().res || {})[+id];
      if (c && F.hyg) F.hyg.showResults([c], "/p/preflight");
    },
    // Cleaned copies → Downloads (MediaStore Download/FOCA-rs), one by one.
    "v2pf-save": () => {
      const st = PF();
      const list = Object.values(st.res || {}).filter(c => c.path);
      let n = 0;
      list
        .reduce(
          (p, c) =>
            p.then(() =>
              F.api.platform_save({ path: c.path, name: c.name }).then(
                r => {
                  if (r && r.ok) n++;
                },
                () => {},
              ),
            ),
          Promise.resolve(),
        )
        .then(() =>
          F.snack(
            n
              ? `${esc(F.t("preflight.saved_downloads", "Сохранено в «Загрузки»:"))} ${n}`
              : F.t("preflight.nothing_save", "Нечего сохранять"),
          ),
        );
    },
    // Resetting results offers Undo.
    "v2pf-reset": () => {
      const prev = state.pf;
      state.pf = null;
      F.render(true);
      F.snack(F.t("preflight.check_reset", "Проверка сброшена"), {
        action: () => {
          state.pf = prev;
          F.render(true);
        },
      });
    },
  });
  F.on("db", e => {
    if (e.kind === "project" || e.kind === "reset") state.pf = null;
  });

  // ================= entry points: ⋮ menu item =================
  const TOOLS = () => [
    [
      "graph",
      F.t("data.relationship_graph", "Граф связей"),
      F.t("tools.layers_clusters_link_chain", "Слои, кластеры и цепочка связи"),
      "/p/graph",
    ],
    [
      "shield",
      () => F.t("insights.attack_paths", "Пути компрометации"),
      F.t("tools.penetration_chains_choke_points", "Цепочки проникновения и точки блокировки"),
      "/p/attack-paths",
    ],
    [
      "net",
      F.t("tools.internal_network_diagram", "Схема внутренней сети"),
      F.t("tools.domain_servers_pcs_users", "Домен, серверы, ПК и пользователи"),
      "/p/netmap",
    ],
    [
      "pin",
      F.t("map.gps_map", "Карта GPS"),
      F.t("tools.where_photos_coordinates_were", "Где сделаны фото с координатами"),
      "/p/map",
    ],
    [
      "history",
      F.t("timeline.timeline", "Таймлайн"),
      F.t("tools.documents_year_activity_hours", "Документы по годам и часы активности"),
      "/p/timeline",
    ],
    [
      "v2-bell",
      F.t("monitor.monitoring", "Мониторинг"),
      F.t("tools.repeat_scans_notifications", "Повторные сканы и уведомления"),
      "/p/monitor",
    ],
    [
      "v2-diff",
      F.t("diff.what_changed", "Что изменилось"),
      F.t("tools.comparison_two_scans", "Сравнение двух сканов"),
      "/p/diff",
    ],
    [
      "spark",
      F.t("menu.ai", "ИИ-сводка"),
      F.t("tools.risks_recommendations_client", "Риски и рекомендации для заказчика"),
      "/p/ai",
    ],
    [
      "plug",
      F.t("settings.plugins", "Плагины"),
      F.t("tools.webassembly_modules", "Модули WebAssembly"),
      "/settings/plugins",
    ],
    [
      "shield",
      F.t("preflight.pre_publication_check", "Проверка перед публикацией"),
      F.t("tools.what_will_leak_from_files_how", "Что утечёт из файлов и как это очистить"),
      "/p/preflight",
    ],
    [
      "app",
      F.t("tools.introduction", "Знакомство"),
      F.t("tools.first_run_screens", "Экраны первого запуска"),
      "/welcome",
    ],
  ];
  F.actions["v2-tools"] = () =>
    F.sheet({
      title: F.t("tools.tools", "Инструменты"),
      html: TOOLS()
        .map(([i, t, s, p]) => {
          const title = typeof t === "function" ? t() : t;
          const route = typeof p === "function" ? p() : p;
          return `<div class="srow" data-act="go:${route}">${ic(i)}<span class="lbl">${esc(title)}<small>${esc(s)}</small></span></div>`;
        })
        .join(""),
    });
  // "Tools" item in the core's ⋮ menu (before Settings).
  if (!F.menuItems.some(m => m.id === "v2-tools"))
    F.menuItems.push({
      id: "v2-tools",
      order: 40,
      icon: "v2-tools",
      label: () => F.t("tools.tools", "Инструменты"),
      sub: () =>
        F.t("tools.graph_map_timeline_ai_pre", "Граф, карта, таймлайн, ИИ, проверка перед публикацией"),
      act: "v2-tools",
      chev: true,
      show: () => !!F.project,
    });
})();
