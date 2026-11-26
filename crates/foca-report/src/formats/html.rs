//! Self-contained HTML report: inline CSS, no JS or external resources, A4, light theme.
//!
//! Every string from data goes through `Ctx::h` (secret masking + escaping) or `safe::html`;
//! only `http(s)` links are clickable (`safe::safe_href`).

use std::fmt::Write as _;

use foca_core::api::Finding;
use foca_core::Severity;

use crate::data::{dmy, sev_id, SEV_ORDER};
use crate::i18n;
use crate::opts::{Logo, Template};
use crate::page::{CSP, CSS};
use crate::safe::{html as esc, safe_href};
use crate::table::html_table;
use crate::Ctx;

pub(crate) fn render(c: &Ctx) -> String {
    let t = c.t;
    let s = &c.o.sections;
    let mut h = String::with_capacity(64 * 1024);
    let title = format!("{} - {}", t.title, c.snap.project.name);
    let _ = write!(
        h,
        "<!DOCTYPE html>\n<html lang=\"{}\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"generator\" content=\"{}\">\n<meta name=\"referrer\" content=\"no-referrer\">\n\
         <title>{}</title>\n<style>\n{CSS}</style>\n</head>\n<body>\n",
        c.o.lang.code(),
        esc(crate::GENERATOR),
        c.h(&title)
    );
    if c.o.tpl == Template::Data {
        let _ = writeln!(
            h,
            "<header class=\"head-data\"><h1>{}</h1><div class=\"muted\">{} · {} · {}</div></header>",
            c.h(&c.snap.project.name),
            esc(c.tpl_label()),
            c.h(&c.snap.scope.client),
            esc(&c.date())
        );
    } else {
        cover(c, &mut h);
        toc(c, &mut h);
    }
    if let Some((title, body)) = i18n::incomplete_banner(c.o.lang, &c.snap.scans) {
        let _ = writeln!(
            h,
            "<p class=\"warn\"><b>⚠ {}</b> {}</p>",
            esc(title),
            esc(&body)
        );
    }
    ai_summary(c, &mut h);
    if s.summary {
        summary(c, &mut h);
    }
    if s.scope {
        scope(c, &mut h);
    }
    if s.findings {
        findings(c, &mut h);
    }
    if s.fixed {
        fixed(c, &mut h);
    }
    if s.people {
        people(c, &mut h);
    }
    if s.infra {
        infra(c, &mut h);
    }
    visuals(c, &mut h);
    if s.docs {
        docs(c, &mut h);
    }
    if s.log {
        log(c, &mut h);
    }
    if s.appx {
        appx(c, &mut h);
    }
    if c.o.custody {
        crate::sections::custody::render_html(c, &mut h);
    }
    let _ = write!(
        h,
        "<footer class=\"gen\"><span>{} {} · {}</span><span>{}</span></footer>\n</body>\n</html>\n",
        esc(t.generator),
        esc(crate::GENERATOR),
        esc(&c.date()),
        esc(t.conf)
    );
    h
}

/// Optional AI-assisted executive summary: labelled, escaped, secrets masked.
fn ai_summary(c: &Ctx, h: &mut String) {
    let Some(a) = c.ai_summary() else { return };
    section_open(h, "ai-summary", i18n::ai_summary_title(c.o.lang));
    let _ = writeln!(h, "<p class=\"warn\">{}</p>", esc(&c.ai_summary_note(a)));
    let mut in_list = false;
    for b in crate::ai_blocks(&a.text) {
        let item = matches!(b, crate::AiBlock::Item(_));
        if item && !in_list {
            h.push_str("<ul>");
        } else if !item && in_list {
            h.push_str("</ul>\n");
        }
        in_list = item;
        match b {
            crate::AiBlock::Head(t) => {
                let _ = writeln!(h, "<h4>{}</h4>", c.h(&t));
            }
            crate::AiBlock::Item(t) => {
                let _ = write!(h, "<li>{}</li>", c.h(&t));
            }
            crate::AiBlock::Para(t) => {
                let _ = writeln!(h, "<p>{}</p>", c.h(&t));
            }
        }
    }
    if in_list {
        h.push_str("</ul>\n");
    }
    h.push_str("</section>\n");
}

fn section_open(h: &mut String, id: &str, title: &str) {
    let _ = write!(h, "<section id=\"{id}\">\n<h2>{}</h2>\n", esc(title));
}

fn badge(c: &Ctx, s: Severity) -> String {
    format!(
        "<span class=\"badge {}\">{}</span>",
        sev_id(s),
        esc(c.sev(s))
    )
}

fn empty(h: &mut String, text: &str) {
    let _ = writeln!(h, "<p class=\"empty\">{}</p>", esc(text));
}

/// Legal entity forms, skipped when building logo initials.
const ORG_FORMS: &[&str] = &[
    "тов", "тоо", "ооо", "пат", "ат", "прат", "пао", "зао", "оао", "фоп", "чп", "пп", "ип", "llc",
    "ltd", "inc", "gmbh", "corp", "plc", "llp", "ag", "sa", "co",
];

/// Returns logo initials from a company name, skipping quotes and legal forms
/// (`LLC "Cyber Audit"` → `CA`).
pub(crate) fn initials(s: &str) -> String {
    let i: String = s
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| !w.is_empty())
        .filter(|w| !ORG_FORMS.contains(&w.trim_end_matches('.').to_lowercase().as_str()))
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect();
    if i.is_empty() {
        "F".into()
    } else {
        i.to_uppercase()
    }
}

fn cover(c: &Ctx, h: &mut String) {
    let t = c.t;
    let sc = &c.snap.scope;
    let logo = match &c.o.logo {
        Logo::None => String::new(),
        Logo::Initials => format!(
            "<div class=\"initials\" aria-hidden=\"true\">{}</div>",
            esc(&initials(&c.o.company))
        ),
        // The MIME type comes from a whitelisted signature and the base64 alphabet is validated.
        Logo::Image { mime, b64 } => format!(
            "<img src=\"data:{};base64,{}\" alt=\"\">",
            esc(mime),
            esc(b64)
        ),
    };
    let _ = write!(
        h,
        "<header class=\"cover\">\n<div class=\"top\"><div class=\"logo\">{logo}</div><div class=\"conf\">{}</div></div>\n\
         <div class=\"title\"><div class=\"kicker\">{}</div><h1>{}</h1><div class=\"proj\">{}</div></div>\n<dl>\n",
        esc(t.conf),
        esc(c.tpl_label()),
        esc(t.title),
        c.h(&c.snap.project.name)
    );
    let mut kv = |k: &str, v: String| {
        if !v.is_empty() {
            let _ = writeln!(h, "<dt>{}</dt><dd>{v}</dd>", esc(k));
        }
    };
    let client = if sc.client.is_empty() {
        &c.snap.project.client
    } else {
        &sc.client
    };
    kv(t.client, c.h(client));
    kv(t.by, c.h(&c.o.company));
    kv(t.date, esc(&c.date()));
    kv(t.tz, esc(&c.tz()));
    h.push_str("</dl>\n</header>\n");
}

fn toc(c: &Ctx, h: &mut String) {
    let t = c.t;
    let v = i18n::viz(c.o.lang);
    let s = &c.o.sections;
    let custody = crate::sections::custody::labels(c.o.lang);
    let items: Vec<(&str, &str, bool)> = vec![
        (
            "ai-summary",
            i18n::ai_summary_title(c.o.lang),
            c.ai_summary().is_some(),
        ),
        ("summary", t.summary, s.summary),
        ("scope", t.scope, s.scope),
        ("findings", t.findings, s.findings),
        ("fixed", t.fixed, s.fixed),
        ("people", t.people, s.people),
        ("infra", t.infra, s.infra),
        ("graph", v.graph, !c.vis.graph.nodes.is_empty()),
        ("netmap", v.netmap, !c.vis.netmap.nodes.is_empty()),
        ("timeline", v.timeline, !c.vis.timeline.events.is_empty()),
        ("activity", v.activity, c.vis.activity.has_data()),
        ("docs", t.docs, s.docs),
        ("log", t.log, s.log),
        ("appx", t.appx, s.appx),
        ("custody", custody.title, c.o.custody),
    ];
    if c.o.tpl != Template::Full {
        return;
    }
    let _ = write!(h, "<nav class=\"toc\"><h2>{}</h2><ol>", esc(t.toc));
    for (id, title, on) in items {
        if on {
            let _ = write!(h, "<li><a href=\"#{id}\">{}</a></li>", esc(title));
        }
    }
    h.push_str("</ol></nav>\n");
}

/// Renders the diagram sections (link graph, network map, chronology, activity) for the
/// parts that have data. The SVG is static markup: the CSP has no `script-src`, and inline
/// `<svg>` elements are document content, not fetched resources, so the policy stays strict.
fn visuals(c: &Ctx, h: &mut String) {
    use crate::svg;
    let l = c.o.lang;
    let v = i18n::viz(l);
    let figs = [
        ("graph", v.graph, svg::graph::render(&c.vis.graph, l), true),
        (
            "netmap",
            v.netmap,
            svg::netmap::render(&c.vis.netmap, l),
            false,
        ),
        (
            "timeline",
            v.timeline,
            svg::timeline::render(&c.vis.timeline, l),
            false,
        ),
        (
            "activity",
            v.activity,
            svg::heatmap::render(&c.vis.activity, l),
            false,
        ),
    ];
    for (id, title, fig, wide) in figs {
        let Some(f) = fig else { continue };
        let _ = write!(
            h,
            "<section id=\"{id}\" class=\"viz-sec\">\n<h2>{}</h2>\n",
            esc(title)
        );
        let _ = writeln!(
            h,
            "<div class=\"viz{}\">{}</div>\n<p class=\"small muted\">{}</p>\n</section>",
            if wide { " wide" } else { "" },
            f.svg,
            esc(&f.caption)
        );
    }
}

/// Renders an inline SVG with horizontal bars per severity.
fn chart(c: &Ctx) -> String {
    let counts = c.res.counts;
    let max = SEV_ORDER
        .iter()
        .map(|s| counts.get(*s))
        .max()
        .unwrap_or(0)
        .max(1);
    let colors = ["#b91c1c", "#c2410c", "#a16207", "#1d4ed8", "#475569"];
    let (w, row) = (360.0_f64, 24.0_f64);
    let mut s = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {w} {}\" role=\"img\" aria-label=\"{}\">",
        row * 5.0 + 4.0,
        esc(c.t.by_sev)
    );
    for (i, sev) in SEV_ORDER.iter().enumerate() {
        let n = counts.get(*sev);
        let y = 2.0 + row * i as f64;
        let bw = 220.0 * n as f64 / max as f64;
        let _ = write!(
            s,
            "<text x=\"0\" y=\"{:.0}\" font-size=\"11\" fill=\"#334155\">{}</text>\
             <rect x=\"96\" y=\"{:.0}\" width=\"220\" height=\"14\" rx=\"3\" fill=\"#f1f5f9\"/>\
             <rect x=\"96\" y=\"{:.0}\" width=\"{bw:.1}\" height=\"14\" rx=\"3\" fill=\"{}\"/>\
             <text x=\"324\" y=\"{:.0}\" font-size=\"11\" font-weight=\"700\" fill=\"#0f172a\">{n}</text>",
            y + 12.0,
            esc(c.sev(*sev)),
            y + 1.0,
            y + 1.0,
            colors[i],
            y + 12.0
        );
    }
    s.push_str("</svg>");
    s
}

fn summary(c: &Ctx, h: &mut String) {
    let t = c.t;
    section_open(h, "summary", t.summary);
    let lvl = c.res.risk_level.as_str();
    let score = c
        .res
        .risk
        .map(|r| format!("{r}<small>/100</small>"))
        .unwrap_or_else(|| "-".into());
    let _ = writeln!(
        h,
        "<div class=\"riskbox\"><div class=\"risk {lvl}\"><div class=\"s\">{}</div><div class=\"n\">{score}</div>\
         <div class=\"l\">{}</div><div class=\"s\">{}</div></div><div class=\"chart\"><h4>{}</h4>{}</div></div>",
        esc(t.risk),
        esc(i18n::risk_level(c.o.lang, lvl)),
        esc(t.risk_by),
        esc(t.by_sev),
        chart(c)
    );
    if c.o.tpl != Template::Data {
        let n = c.res.total;
        let cc = t
            .summary_text_c
            .replace("{c}", &c.res.counts.crit.to_string())
            .replace("{h}", &c.res.counts.high.to_string());
        let _ = write!(h, "<p>{}: <b>{n}</b>; {}.", esc(t.summary_text_n), esc(&cc));
        if !c.fixed.is_empty() {
            let _ = write!(h, " {}: <b>{}</b>.", esc(t.summary_fixed), c.fixed.len());
        }
        h.push_str("</p>\n");
        if let Some(n) = c.oos_caveat() {
            let _ = writeln!(h, "<p class=\"warn\">{}</p>", esc(&n));
        }
        if !c.main.is_empty() {
            let _ = write!(h, "<h4>{}</h4><ul>", esc(t.summary_top));
            for f in c.main.iter().take(5) {
                let _ = write!(
                    h,
                    "<li>{} {} <span class=\"muted\">({})</span></li>",
                    badge(c, f.sev),
                    c.h(&f.title),
                    c.h(&f.host)
                );
            }
            h.push_str("</ul>\n");
        }
        if c.res.counts.crit > 0 {
            let _ = writeln!(h, "<p><b>{}</b></p>", esc(t.summary_crit_advice));
        }
    }
    // Summary.
    let ov = &c.ov;
    h.push_str("<div class=\"grid2\"><div>");
    let _ = write!(h, "<h4>{}</h4>", esc(t.docs_by_type));
    if ov.docs_by_type.is_empty() {
        empty(h, t.no_data);
    } else {
        let rows: Vec<Vec<String>> = ov
            .docs_by_type
            .iter()
            .map(|(e, n)| vec![c.h(e), n.to_string()])
            .collect();
        html_table(h, &[t.kind, t.count], &rows, &[1]);
    }
    let _ = write!(h, "<h4>{}</h4>", esc(t.infra_found));
    let infra_rows = vec![
        vec![esc(t.hosts), ov.hosts.to_string()],
        vec![esc(t.internal), ov.hosts_internal.to_string()],
        vec![esc(t.pcs), ov.pcs.to_string()],
        vec![esc(t.printers), ov.printers.to_string()],
        vec![esc(t.paths), ov.paths.to_string()],
        vec![esc(t.emails), ov.emails.to_string()],
    ];
    html_table(h, &[t.kind, t.count], &infra_rows, &[1]);
    h.push_str("</div><div>");
    let _ = write!(h, "<h4>{}</h4>", esc(t.top_people));
    if ov.top_people.is_empty() {
        empty(h, t.no_data);
    } else {
        let rows: Vec<Vec<String>> = ov
            .top_people
            .iter()
            .map(|(l, n, d)| vec![c.h(l), c.h(n), d.to_string()])
            .collect();
        html_table(h, &[t.login, t.name, t.n_docs], &rows, &[2]);
    }
    let _ = write!(h, "<h4>{}</h4>", esc(t.top_software));
    if ov.top_software.is_empty() {
        empty(h, t.no_data);
    } else {
        let rows: Vec<Vec<String>> = ov
            .top_software
            .iter()
            .map(|(n, d)| vec![c.h(n), d.to_string()])
            .collect();
        html_table(h, &[t.software, t.n_docs], &rows, &[1]);
    }
    if !ov.host_software.is_empty() {
        let _ = write!(h, "<h4>{}</h4>", esc(t.host_software));
        let rows: Vec<Vec<String>> = ov
            .host_software
            .iter()
            .map(|(n, k)| vec![c.h(n), k.to_string()])
            .collect();
        html_table(h, &[t.software, t.n_hosts], &rows, &[1]);
    }
    h.push_str("</div></div>\n");
    let _ = write!(h, "<h4>{}</h4>", esc(t.eol_software));
    if ov.eol_software.is_empty() {
        empty(h, t.no_data);
    } else {
        let rows: Vec<Vec<String>> = ov
            .eol_software
            .iter()
            .map(|(n, d, cve)| {
                vec![
                    c.h(n),
                    c.h(&crate::data::eol_label(d, c.o.lang)),
                    cve.map_or_else(|| "-".into(), |x| x.to_string()),
                ]
            })
            .collect();
        html_table(h, &[t.software, t.eol, t.cve], &rows, &[2]);
    }
    h.push_str("</section>\n");
}

fn scope(c: &Ctx, h: &mut String) {
    let t = c.t;
    let sc = &c.snap.scope;
    section_open(h, "scope", t.scope);
    h.push_str("<dl class=\"kv\">");
    let mut kv = |k: &str, v: String| {
        let v = if v.is_empty() { "-".to_string() } else { v };
        let _ = write!(h, "<dt>{}</dt><dd>{v}</dd>", esc(k));
    };
    kv(t.client, c.h(&sc.client));
    let contact = [sc.contact.as_str(), sc.phone.as_str()]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    kv(t.contact, c.h(&contact));
    h.push_str("</dl>\n");
    // The engagement basis is an optional authorization note; the section is omitted when empty.
    if !sc.basis.trim().is_empty() {
        let _ = writeln!(h, "<h4>{}</h4><p>{}</p>", esc(t.basis), c.h(&sc.basis));
    }
    let _ = write!(h, "<h4>{}</h4>", esc(t.targets));
    if sc.targets.is_empty() {
        empty(h, t.no_data);
    } else {
        let rows: Vec<Vec<String>> = sc
            .targets
            .iter()
            .map(|x| {
                vec![
                    format!("<span class=\"mono\">{}</span>", c.h(&x.v)),
                    c.h(&x.kind),
                ]
            })
            .collect();
        html_table(h, &[t.targets, t.kind], &rows, &[]);
    }
    let (title, list) = (t.excl, &sc.excl);
    {
        if !list.is_empty() {
            let _ = write!(h, "<h4>{}</h4><p>", esc(title));
            for x in list {
                let _ = write!(h, "<span class=\"tag\">{}</span>", c.h(x));
            }
            h.push_str("</p>\n");
        }
    }
    h.push_str("</section>\n");
}

fn link_or_text(c: &Ctx, url: &str) -> String {
    let shown = c.r(url);
    match safe_href(&shown) {
        // Only a link left untouched by secret masking is clickable.
        Some(u) if shown == url => format!(
            "<a href=\"{}\" rel=\"noopener noreferrer nofollow\">{}</a>",
            esc(u),
            esc(u)
        ),
        _ => format!("<span class=\"mono\">{}</span>", esc(&shown)),
    }
}

fn findings_table(c: &Ctx, h: &mut String, list: &[&Finding], with_status: bool) {
    let t = c.t;
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|f| {
            let mut r = vec![c.fref(f), badge(c, f.sev), c.h(&f.title), c.h(&f.host)];
            if with_status {
                r.push(esc(c.status(f.status)));
            } else {
                r.push(c.h(&f.mitre));
            }
            r
        })
        .collect();
    let last = if with_status { t.status } else { t.mitre };
    html_table(h, &["ID", t.sev, t.finding, t.host, last], &rows, &[]);
}

fn finding_card(c: &Ctx, h: &mut String, f: &Finding) {
    let t = c.t;
    let _ = write!(
        h,
        "<article class=\"finding {}\" id=\"f-{}\">\n<h3><span class=\"id\">{}</span><span>{}</span> {}</h3>\n<div class=\"meta\">",
        sev_id(f.sev),
        f.id,
        c.fref(f),
        c.h(&f.title),
        badge(c, f.sev)
    );
    let mut meta = vec![
        format!("{}: {}", esc(t.status), esc(c.status(f.status))),
        format!("{}: {}", esc(t.host), c.h(&f.host)),
    ];
    if !f.category.is_empty() {
        meta.push(format!("{}: {}", esc(t.category), c.h(&f.category)));
    }
    if !f.cve.is_empty() {
        meta.push(c.h(&f.cve.join(", ")));
    }
    if let Some(cv) = f.cvss {
        meta.push(format!("CVSS {cv:.1}"));
    }
    if let Some(s) = &f.first_scan {
        meta.push(format!("{}: {}", esc(t.first_seen), c.h(&c.scan_label(s))));
    }
    for m in meta {
        let _ = write!(h, "<span>{m}</span>");
    }
    h.push_str("</div>\n");
    if !f.description.is_empty() {
        let _ = writeln!(
            h,
            "<h4>{}</h4><p class=\"txt\">{}</p>",
            esc(t.description),
            c.h(&f.description)
        );
    }
    if !f.evidence.is_empty() {
        let _ = writeln!(
            h,
            "<h4>{}</h4><pre class=\"ev\">{}</pre>",
            esc(t.evidence),
            c.h(&f.evidence)
        );
    }
    if !f.request.is_empty() {
        let _ = writeln!(h, "<pre class=\"ev\">{}</pre>", c.h(&f.request));
    }
    if let Some(u) = f.url.as_deref().filter(|u| !u.is_empty()) {
        let _ = writeln!(
            h,
            "<p class=\"small\">{}: {}</p>",
            esc(t.url),
            link_or_text(c, u)
        );
    }
    if !f.recommendation.is_empty() {
        let _ = writeln!(
            h,
            "<h4>{}</h4><p class=\"txt\">{}</p>",
            esc(t.recommendation),
            c.h(&f.recommendation)
        );
    }
    if !f.mitre.is_empty() {
        let _ = writeln!(
            h,
            "<p class=\"small\"><b>{}:</b> {}</p>",
            esc(t.mitre),
            c.h(&f.mitre)
        );
    }
    let p = &f.provenance;
    let mut prov = Vec::new();
    if !p.rule.is_empty() {
        prov.push(format!(
            "{}: <span class=\"mono\">{}</span>",
            esc(t.rule),
            c.h(&p.rule)
        ));
    }
    if !p.fields.is_empty() {
        prov.push(format!("{}: {}", esc(t.fields), c.h(&p.fields.join(", "))));
    }
    let docs: Vec<u64> = if p.docs.is_empty() {
        f.doc.into_iter().collect()
    } else {
        p.docs.clone()
    };
    if !docs.is_empty() {
        let names: Vec<String> = docs.iter().map(|d| c.doc_name(*d)).collect();
        prov.push(format!(
            "{}: {}",
            esc(t.source_docs),
            c.h(&names.join(", "))
        ));
    }
    if f.active {
        prov.push(format!("{} ({})", esc(t.active_module), c.h(&f.module)));
    }
    if !prov.is_empty() {
        let _ = writeln!(
            h,
            "<div class=\"prov\"><b>{}:</b> {}</div>",
            esc(t.provenance),
            prov.join("; ")
        );
    }
    for n in &f.notes {
        let _ = writeln!(
            h,
            "<div class=\"note\"><span class=\"muted\">{} · {}</span><br><span class=\"txt\">{}</span></div>",
            c.h(&n.who),
            c.h(&c.ts(&n.time)),
            c.h(&n.text)
        );
    }
    h.push_str("</article>\n");
}

fn findings(c: &Ctx, h: &mut String) {
    let t = c.t;
    section_open(h, "findings", t.findings);
    if c.main.is_empty() {
        empty(h, t.none);
    } else if c.o.tpl == Template::Full {
        for f in &c.main {
            finding_card(c, h, f);
        }
    } else {
        findings_table(c, h, &c.main, false);
    }
    h.push_str("</section>\n");
}

fn fixed(c: &Ctx, h: &mut String) {
    let t = c.t;
    section_open(h, "fixed", t.fixed);
    if c.fixed.is_empty() {
        empty(h, t.no_data);
    } else {
        let rows: Vec<Vec<String>> = c
            .fixed
            .iter()
            .map(|f| {
                vec![
                    c.fref(f),
                    badge(c, f.sev),
                    c.h(&f.title),
                    c.h(&f.host),
                    c.h(&f
                        .fixed_scan
                        .as_deref()
                        .map(|s| c.scan_label(s))
                        .unwrap_or_else(|| "-".into())),
                ]
            })
            .collect();
        html_table(h, &["ID", t.sev, t.finding, t.host, t.fixed_in], &rows, &[]);
    }
    h.push_str("</section>\n");
}

fn people(c: &Ctx, h: &mut String) {
    let t = c.t;
    let snap = c.snap;
    section_open(h, "people", t.people);
    if snap.people.is_empty() {
        empty(h, t.no_data);
    } else {
        let rows: Vec<Vec<String>> = snap
            .people
            .iter()
            .map(|p| {
                let mut login = format!("<span class=\"mono\">{}</span>", c.h(&p.login));
                if p.service {
                    let _ = write!(login, " <span class=\"tag\">{}</span>", esc(t.service_acc));
                }
                vec![
                    login,
                    c.h(&p.name),
                    c.h(&crate::ftext::role(&p.role, c.o.lang)),
                    c.h(p.pc.as_deref().unwrap_or("")),
                    c.h(&p.emails.join(", ")),
                    p.docs.to_string(),
                ]
            })
            .collect();
        html_table(
            h,
            &[t.login, t.name, t.role, t.pc, t.emails, t.n_docs],
            &rows,
            &[5],
        );
    }
    if !snap.patterns.is_empty() {
        let _ = write!(h, "<h4>{}</h4>", esc(t.pattern));
        let rows: Vec<Vec<String>> = snap
            .patterns
            .iter()
            .map(|p| {
                vec![
                    format!(
                        "<span class=\"mono\">{}@{}</span>",
                        c.h(&p.p),
                        c.h(&p.domain)
                    ),
                    c.h(&p.ex),
                    format!("{}%", p.conf),
                    p.n.to_string(),
                ]
            })
            .collect();
        html_table(h, &[t.pattern, t.emails, "%", t.count], &rows, &[2, 3]);
    }
    if !snap.emails.is_empty() {
        let _ = write!(h, "<h4>{}</h4>", esc(t.emails));
        let rows: Vec<Vec<String>> = snap
            .emails
            .iter()
            .map(|e| {
                vec![
                    format!("<span class=\"mono\">{}</span>", c.h(&e.addr)),
                    c.h(e.name.as_deref().unwrap_or("")),
                    esc(c.yes_no(e.found)),
                    c.h(&e.src),
                ]
            })
            .collect();
        html_table(
            h,
            &[t.address, t.name, t.found_in_docs, t.provenance],
            &rows,
            &[],
        );
    }
    h.push_str("</section>\n");
}

fn infra(c: &Ctx, h: &mut String) {
    let t = c.t;
    let snap = c.snap;
    section_open(h, "infra", t.infra);
    let _ = write!(h, "<h3>{}</h3>", esc(t.hosts));
    if snap.hosts.is_empty() {
        empty(h, t.no_data);
    } else {
        let rows: Vec<Vec<String>> = snap
            .hosts
            .iter()
            .map(|x| {
                vec![
                    format!("<span class=\"mono\">{}</span>", c.h(&x.name)),
                    c.h(&x.ip),
                    c.h(&crate::ftext::role(&x.role, c.o.lang)),
                    c.h(&x.tech),
                    esc(c.yes_no(x.internal)),
                    esc(&crate::ftext::scope_label(&x.scope, c.o.lang)),
                ]
            })
            .collect();
        html_table(
            h,
            &[t.host, t.ip, t.role, t.tech, t.internal, t.scope_col],
            &rows,
            &[],
        );
        crate::sections::ports::html(c, h);
        crate::sections::infra::html(c, h);
    }
    if !snap.pcs.is_empty() {
        let _ = write!(h, "<h3>{}</h3>", esc(t.pcs));
        let rows: Vec<Vec<String>> = snap
            .pcs
            .iter()
            .map(|p| {
                vec![
                    format!("<span class=\"mono\">{}</span>", c.h(&p.name)),
                    c.h(&p.kind),
                    c.h(&p.users.join(", ")),
                    c.h(p.ip.as_deref().unwrap_or("")),
                    p.docs.to_string(),
                ]
            })
            .collect();
        html_table(h, &[t.pc, t.kind, t.users, t.ip, t.n_docs], &rows, &[4]);
    }
    if !snap.software.is_empty() {
        let _ = write!(h, "<h3>{}</h3>", esc(t.software));
        let rows: Vec<Vec<String>> = snap
            .software
            .iter()
            .map(|s| {
                let eol = if s.eol {
                    format!(
                        "<span class=\"badge high\">EOL</span> {}",
                        c.h(&crate::data::eol_label(
                            s.eol_date.as_deref().unwrap_or(""),
                            c.o.lang
                        ))
                    )
                } else {
                    String::new()
                };
                vec![
                    c.h(&s.name),
                    c.h(&s.ver),
                    eol,
                    crate::data::sw_cve(s).map_or_else(|| "-".into(), |x| x.to_string()),
                    s.docs.to_string(),
                ]
            })
            .collect();
        html_table(
            h,
            &[t.software, t.version, t.eol, t.cve, t.n_docs],
            &rows,
            &[3, 4],
        );
    }
    if !snap.paths.is_empty() {
        let _ = write!(h, "<h3>{}</h3>", esc(t.paths));
        let rows: Vec<Vec<String>> = snap
            .paths
            .iter()
            .map(|p| {
                vec![
                    format!("<span class=\"mono\">{}</span>", c.h(&p.path)),
                    c.h(p.user.as_deref().unwrap_or("")),
                    c.h(p.host.as_deref().unwrap_or("")),
                    p.docs.to_string(),
                ]
            })
            .collect();
        html_table(h, &[t.path, t.login, t.host, t.n_docs], &rows, &[3]);
    }
    if !snap.printers.is_empty() {
        let _ = write!(h, "<h3>{}</h3>", esc(t.printers));
        let rows: Vec<Vec<String>> = snap
            .printers
            .iter()
            .map(|p| {
                vec![
                    c.h(&p.name),
                    c.h(p.host.as_deref().unwrap_or("")),
                    p.docs.to_string(),
                ]
            })
            .collect();
        html_table(h, &[t.name, t.host, t.n_docs], &rows, &[2]);
    }
    site_found(c, h);
    crate::sections::recon::html(c, h);
    h.push_str("</section>\n");
}

/// Renders the "found on site" subsection: forgotten documents, backups, service files and
/// directory listings (the `fuzz` module).
fn site_found(c: &Ctx, h: &mut String) {
    let t = c.t;
    let list: Vec<&&Finding> = c.main.iter().filter(|f| f.module == "fuzz").collect();
    if list.is_empty() {
        return;
    }
    let _ = write!(h, "<h3 id=\"site\">{}</h3>", esc(t.site_found));
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|f| {
            let ev: String = f
                .evidence
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(160)
                .collect();
            vec![
                badge(c, f.sev),
                c.h(&f.title),
                f.url
                    .as_deref()
                    .map(|u| link_or_text(c, u))
                    .unwrap_or_default(),
                format!("<span class=\"mono\">{}</span>", c.h(&ev)),
            ]
        })
        .collect();
    html_table(h, &[t.sev, t.finding, t.url, t.evidence], &rows, &[]);
}

fn docs(c: &Ctx, h: &mut String) {
    let t = c.t;
    section_open(h, "docs", t.docs);
    let live: Vec<_> = c.snap.docs.iter().filter(|d| !d.deleted).collect();
    if live.is_empty() {
        empty(h, t.no_data);
    } else {
        let rows: Vec<Vec<String>> = live
            .iter()
            .map(|d| {
                let name = if d.url.is_empty() {
                    c.h(&d.name)
                } else {
                    format!(
                        "{}<br><span class=\"small\">{}</span>",
                        c.h(&d.name),
                        link_or_text(c, &d.url)
                    )
                };
                vec![
                    d.id.to_string(),
                    name,
                    c.h(&d.title),
                    c.h(d.author.as_deref().unwrap_or("")),
                    c.h(&d
                        .software
                        .as_deref()
                        .map(|x| crate::data::sw_label_by_id(c.snap, x, c.o.lang))
                        .unwrap_or_default()),
                    c.h(&dmy(d.created_at.as_deref().unwrap_or(""))),
                    c.h(&d.flags.join(", ")),
                ]
            })
            .collect();
        html_table(
            h,
            &[
                "#",
                t.file,
                t.doc_title,
                t.author,
                t.software,
                t.created,
                t.flags,
            ],
            &rows,
            &[0, 5],
        );
    }
    crate::sections::forensics::html(c, h);
    h.push_str("</section>\n");
}

fn log(c: &Ctx, h: &mut String) {
    let t = c.t;
    let ls = &c.ls;
    section_open(h, "log", t.log);
    if ls.total == 0 {
        empty(h, t.log_empty);
        h.push_str("</section>\n");
        return;
    }
    let _ = writeln!(
        h,
        "<dl class=\"kv\"><dt>{}</dt><dd><b>{}</b></dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}: {} ({})</dd></dl>",
        esc(t.log_total),
        ls.total,
        esc(t.log_passive),
        ls.passive,
        esc(t.log_active),
        ls.active,
        esc(t.log_blocked),
        ls.blocked,
        esc(t.log_hosts_target),
        ls.hosts_target,
        esc(t.log_hosts_third),
        ls.hosts_third,
        esc(t.period),
        c.h(&c.ts(ls.first.as_deref().unwrap_or(""))),
        c.h(&c.ts(ls.last.as_deref().unwrap_or(""))),
        esc(&c.tz())
    );
    let _ = write!(h, "<h4>{}</h4>", esc(t.log_by_module));
    let rows: Vec<Vec<String>> = ls
        .by_module
        .iter()
        .map(|(m, n)| vec![c.h(m), n.to_string()])
        .collect();
    html_table(h, &[t.module, t.count], &rows, &[1]);
    let req_rows = |blocked: bool| -> Vec<Vec<String>> {
        c.log
            .iter()
            .filter(|r| {
                if blocked {
                    r.blocked
                } else {
                    r.active && !r.blocked
                }
            })
            .map(|r| {
                vec![
                    c.h(&c.ts(&r.time)),
                    c.h(&r.method),
                    format!(
                        "<span class=\"mono\">{}</span>",
                        c.h(&crate::ftext::log_text(&r.url, c.o.lang))
                    ),
                    r.status.map(|s| s.to_string()).unwrap_or_default(),
                    c.h(&crate::ftext::log_size_type(
                        r.bytes,
                        r.ctype.as_deref(),
                        c.o.lang,
                    )),
                    c.h(&r.module),
                    c.h(&crate::ftext::log_error_cell(
                        r.note.as_deref(),
                        r.error.as_deref(),
                        c.o.lang,
                    )),
                ]
            })
            .collect()
    };
    for (title, blocked) in [(t.log_active_list, false), (t.log_blocked_list, true)] {
        let _ = write!(h, "<h4>{}</h4>", esc(title));
        let rows = req_rows(blocked);
        if rows.is_empty() {
            empty(h, t.no_data);
        } else {
            html_table(
                h,
                &[
                    t.time,
                    t.method,
                    t.url,
                    t.code,
                    t.size_type,
                    t.module,
                    t.error,
                ],
                &rows,
                &[3],
            );
        }
    }
    h.push_str("</section>\n");
}

fn appx(c: &Ctx, h: &mut String) {
    let t = c.t;
    section_open(h, "appx", t.appx);
    let _ = writeln!(
        h,
        "<h3>{}</h3><p>{}</p>",
        esc(t.method_title),
        esc(t.method_text)
    );
    if let Some(i18n::IncompleteTable { title, head, rows }) =
        i18n::incomplete_sources(c.o.lang, &c.snap.scans)
    {
        let _ = write!(h, "<h3>{}</h3>", esc(title));
        let rows: Vec<Vec<String>> = rows
            .iter()
            .map(|[id, why]| vec![format!("<span class=\"mono\">{}</span>", esc(id)), esc(why)])
            .collect();
        html_table(h, &head, &rows, &[]);
    }
    if !c.snap.scans.is_empty() {
        let _ = write!(h, "<h3>{}</h3>", esc(t.scans));
        let rows: Vec<Vec<String>> = c
            .snap
            .scans
            .iter()
            .map(|s| {
                let profile = if s.profile.is_empty() {
                    &s.profile_id
                } else {
                    &s.profile
                };
                vec![
                    format!("<span class=\"mono\">{}</span>", c.h(&s.id)),
                    c.h(profile),
                    c.h(&c.ts(&s.started_at)),
                    c.h(&c.ts(s.finished_at.as_deref().unwrap_or(""))),
                    c.h(&s.egress),
                    c.h(&s.status),
                ]
            })
            .collect();
        html_table(
            h,
            &["ID", t.profile, t.started, t.finished, t.egress, t.status],
            &rows,
            &[],
        );
    }
    let secrets: Vec<_> = c.snap.secrets.iter().filter(|s| s.kind != "host").collect();
    if !secrets.is_empty() {
        let _ = write!(h, "<h3>{}</h3>", esc(t.secret));
        let rows: Vec<Vec<String>> = secrets
            .iter()
            .map(|s| {
                vec![
                    c.h(&s.kind),
                    c.h(&c.doc_name(s.doc)),
                    c.h(&s.location),
                    badge(c, s.sev),
                    format!(
                        "<span class=\"mono\">{}</span>",
                        esc(&c.red.mask(s.value.expose()))
                    ),
                ]
            })
            .collect();
        html_table(h, &[t.kind, t.file, t.path, t.sev, t.secret], &rows, &[]);
    }
    let _ = write!(h, "<h3>{}</h3><dl class=\"kv\">", esc(t.report_params));
    let min = c.o.min_sev.map(|s| c.sev(s)).unwrap_or(t.all);
    for (k, v) in [
        (t.only_confirmed, c.yes_no(c.o.confirmed)),
        (t.min_sev, min),
        (t.picked_only, c.yes_no(c.o.picked_only)),
        (t.secrets_mode, c.secret_mode()),
    ] {
        let _ = write!(h, "<dt>{}</dt><dd>{}</dd>", esc(k), esc(v));
    }
    h.push_str("</dl>\n</section>\n");
}

#[cfg(test)]
mod tests {
    use super::initials;

    #[test]
    fn logo_initials_skip_org_forms_and_quotes() {
        assert_eq!(initials("ТОВ «Кібер Аудит»"), "КА");
        assert_eq!(initials("ООО \"Альфа Бета\""), "АБ");
        assert_eq!(initials("Contoso Security LLC"), "CS");
        assert_eq!(initials("ФОП Іваненко"), "І");
        assert_eq!(initials("Acme GmbH"), "A");
        assert_eq!(initials("ТОВ"), "F");
        assert_eq!(initials(""), "F");
    }
}
