//! Markdown report for Obsidian: YAML front matter, tables, escaping (`|`, markup, HTML).

use std::fmt::Write as _;

use foca_core::api::Finding;

use crate::data::{dmy, sev_id, SEV_ORDER};
use crate::i18n;
use crate::opts::Template;
use crate::safe::{md as esc, md_code_block, yaml_str};
use crate::table::md_table;
use crate::Ctx;

pub(crate) fn render(c: &Ctx) -> String {
    let t = c.t;
    let s = &c.o.sections;
    let snap = c.snap;
    let mut o = String::with_capacity(32 * 1024);
    // Front matter values are JSON strings (valid YAML scalars) with secrets masked.
    o.push_str("---\n");
    let _ = writeln!(
        o,
        "title: {}",
        yaml_str(&format!("{} - {}", t.title, c.r(&snap.project.name)))
    );
    let _ = writeln!(o, "project: {}", yaml_str(&c.r(&snap.project.name)));
    let _ = writeln!(o, "client: {}", yaml_str(&c.r(&snap.scope.client)));
    let _ = writeln!(o, "date: {}", c.iso_date());
    let _ = writeln!(o, "template: {}", c.o.tpl.id());
    let _ = writeln!(o, "lang: {}", c.o.lang.code());
    match c.res.risk {
        Some(r) => {
            let _ = writeln!(o, "risk: {r}");
        }
        None => o.push_str("risk: null\n"),
    }
    let _ = writeln!(o, "risk_level: {}", c.res.risk_level);
    let _ = writeln!(o, "findings: {}", c.res.total);
    for sev in SEV_ORDER {
        let _ = writeln!(o, "findings_{}: {}", sev_id(sev), c.res.counts.get(sev));
    }
    let _ = writeln!(o, "secrets: {}", c.o.secrets.id());
    let _ = writeln!(o, "generator: {}", yaml_str(crate::GENERATOR));
    o.push_str("tags: [foca, pentest, report]\n---\n\n");
    let _ = writeln!(o, "# {} - {}\n", esc(t.title), c.m(&snap.project.name));
    let _ = writeln!(
        o,
        "> **{}** · {} · {}: {} ({}){}\n",
        esc(t.conf),
        esc(c.tpl_label()),
        esc(t.date),
        esc(&c.date()),
        esc(&c.tz()),
        if c.o.company.is_empty() {
            String::new()
        } else {
            format!(" · {}: {}", esc(t.by), c.m(&c.o.company))
        }
    );
    if let Some((title, body)) = i18n::incomplete_banner(c.o.lang, &c.snap.scans) {
        let _ = writeln!(o, "> **⚠ {}:** {}\n", esc(title), esc(&body));
    }
    ai_summary(c, &mut o);
    if s.summary {
        summary(c, &mut o);
    }
    if s.scope {
        scope(c, &mut o);
    }
    if s.findings {
        let _ = writeln!(o, "## {}\n", esc(t.findings));
        if c.main.is_empty() {
            let _ = writeln!(o, "*{}*\n", esc(t.none));
        } else if c.o.tpl == Template::Full {
            for f in &c.main {
                card(c, &mut o, f);
            }
        } else {
            let rows: Vec<Vec<String>> = c
                .main
                .iter()
                .map(|f| {
                    vec![
                        c.fref(f),
                        esc(c.sev(f.sev)),
                        c.m(&f.title),
                        c.m(&f.host),
                        c.m(&f.mitre),
                    ]
                })
                .collect();
            md_table(
                c.t.no_data,
                &mut o,
                &["ID", t.sev, t.finding, t.host, t.mitre],
                &rows,
            );
        }
    }
    if s.fixed {
        let _ = writeln!(o, "## {}\n", esc(t.fixed));
        if c.fixed.is_empty() {
            let _ = writeln!(o, "*{}*\n", esc(t.no_data));
        } else {
            let rows: Vec<Vec<String>> = c
                .fixed
                .iter()
                .map(|f| {
                    vec![
                        c.fref(f),
                        esc(c.sev(f.sev)),
                        c.m(&f.title),
                        c.m(&f.host),
                        c.m(&f
                            .fixed_scan
                            .as_deref()
                            .map(|s| c.scan_label(s))
                            .unwrap_or_else(|| "-".into())),
                    ]
                })
                .collect();
            md_table(
                c.t.no_data,
                &mut o,
                &["ID", t.sev, t.finding, t.host, t.fixed_in],
                &rows,
            );
        }
    }
    if s.people {
        let _ = writeln!(o, "## {}\n", esc(t.people));
        let rows: Vec<Vec<String>> = snap
            .people
            .iter()
            .map(|p| {
                vec![
                    format!(
                        "{}{}",
                        c.m(&p.login),
                        if p.service {
                            format!(" ({})", esc(t.service_acc))
                        } else {
                            String::new()
                        }
                    ),
                    c.m(&p.name),
                    c.m(&crate::ftext::role(&p.role, c.o.lang)),
                    c.m(p.pc.as_deref().unwrap_or("")),
                    c.m(&p.emails.join(", ")),
                    p.docs.to_string(),
                ]
            })
            .collect();
        md_table(
            c.t.no_data,
            &mut o,
            &[t.login, t.name, t.role, t.pc, t.emails, t.n_docs],
            &rows,
        );
        if !snap.emails.is_empty() {
            let _ = writeln!(o, "### {}\n", esc(t.emails));
            let rows: Vec<Vec<String>> = snap
                .emails
                .iter()
                .map(|e| {
                    vec![
                        c.m(&e.addr),
                        c.m(e.name.as_deref().unwrap_or("")),
                        esc(c.yes_no(e.found)),
                    ]
                })
                .collect();
            md_table(
                c.t.no_data,
                &mut o,
                &[t.address, t.name, t.found_in_docs],
                &rows,
            );
        }
    }
    if s.infra {
        let _ = writeln!(o, "## {}\n", esc(t.infra));
        let _ = writeln!(o, "### {}\n", esc(t.hosts));
        let rows: Vec<Vec<String>> = snap
            .hosts
            .iter()
            .map(|h| {
                vec![
                    c.m(&h.name),
                    c.m(&h.ip),
                    c.m(&crate::ftext::role(&h.role, c.o.lang)),
                    c.m(&h.tech),
                    esc(c.yes_no(h.internal)),
                    esc(&crate::ftext::scope_label(&h.scope, c.o.lang)),
                ]
            })
            .collect();
        md_table(
            c.t.no_data,
            &mut o,
            &[t.host, t.ip, t.role, t.tech, t.internal, t.scope_col],
            &rows,
        );
        crate::sections::ports::md(c, &mut o);
        crate::sections::infra::md(c, &mut o);
        let site: Vec<&&Finding> = c.main.iter().filter(|f| f.module == "fuzz").collect();
        if !site.is_empty() {
            let _ = writeln!(o, "### {}\n", esc(t.site_found));
            let rows: Vec<Vec<String>> = site
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
                        esc(c.sev(f.sev)),
                        c.m(&f.title),
                        c.m(f.url.as_deref().unwrap_or("")),
                        c.m(&ev),
                    ]
                })
                .collect();
            md_table(
                c.t.no_data,
                &mut o,
                &[t.sev, t.finding, t.url, t.evidence],
                &rows,
            );
        }
        crate::sections::recon::md(c, &mut o);
        if !snap.pcs.is_empty() {
            let _ = writeln!(o, "### {}\n", esc(t.pcs));
            let rows: Vec<Vec<String>> = snap
                .pcs
                .iter()
                .map(|p| {
                    vec![
                        c.m(&p.name),
                        c.m(&p.kind),
                        c.m(&p.users.join(", ")),
                        p.docs.to_string(),
                    ]
                })
                .collect();
            md_table(
                c.t.no_data,
                &mut o,
                &[t.pc, t.kind, t.users, t.n_docs],
                &rows,
            );
        }
        if !snap.software.is_empty() {
            let _ = writeln!(o, "### {}\n", esc(t.software));
            let rows: Vec<Vec<String>> = snap
                .software
                .iter()
                .map(|s| {
                    vec![
                        c.m(&s.name),
                        c.m(&s.ver),
                        if s.eol {
                            format!(
                                "EOL {}",
                                c.m(&crate::data::eol_label(
                                    s.eol_date.as_deref().unwrap_or(""),
                                    c.o.lang
                                ))
                            )
                        } else {
                            String::new()
                        },
                        crate::data::sw_cve(s).map_or_else(|| "-".into(), |x| x.to_string()),
                        s.docs.to_string(),
                    ]
                })
                .collect();
            md_table(
                c.t.no_data,
                &mut o,
                &[t.software, t.version, t.eol, t.cve, t.n_docs],
                &rows,
            );
        }
        if !snap.paths.is_empty() {
            let _ = writeln!(o, "### {}\n", esc(t.paths));
            let rows: Vec<Vec<String>> = snap
                .paths
                .iter()
                .map(|p| {
                    vec![
                        c.m(&p.path),
                        c.m(p.user.as_deref().unwrap_or("")),
                        c.m(p.host.as_deref().unwrap_or("")),
                        p.docs.to_string(),
                    ]
                })
                .collect();
            md_table(
                c.t.no_data,
                &mut o,
                &[t.path, t.login, t.host, t.n_docs],
                &rows,
            );
        }
    }
    visuals(c, &mut o);
    if s.docs {
        let _ = writeln!(o, "## {}\n", esc(t.docs));
        let rows: Vec<Vec<String>> = snap
            .docs
            .iter()
            .filter(|d| !d.deleted)
            .map(|d| {
                vec![
                    d.id.to_string(),
                    c.m(&d.name),
                    c.m(d.author.as_deref().unwrap_or("")),
                    c.m(&d
                        .software
                        .as_deref()
                        .map(|x| crate::data::sw_label_by_id(c.snap, x, c.o.lang))
                        .unwrap_or_default()),
                    c.m(&dmy(d.created_at.as_deref().unwrap_or(""))),
                    c.m(&d.flags.join(", ")),
                ]
            })
            .collect();
        md_table(
            c.t.no_data,
            &mut o,
            &["#", t.file, t.author, t.software, t.created, t.flags],
            &rows,
        );
    }
    if s.docs {
        crate::sections::forensics::md(c, &mut o);
    }
    if s.log {
        let _ = writeln!(o, "## {}\n", esc(t.log));
        let ls = &c.ls;
        if ls.total == 0 {
            let _ = writeln!(o, "*{}*\n", esc(t.log_empty));
        } else {
            let _ = writeln!(
                o,
                "- {}: **{}**\n- {}: {}\n- {}: {}\n- {}: {}\n- {}: {}\n- {}: {}\n- {}: {}, {} ({})\n",
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
                c.m(&c.ts(ls.first.as_deref().unwrap_or(""))),
                c.m(&c.ts(ls.last.as_deref().unwrap_or(""))),
                esc(&c.tz())
            );
            let rows: Vec<Vec<String>> = ls
                .by_module
                .iter()
                .map(|(m, n)| vec![c.m(m), n.to_string()])
                .collect();
            md_table(c.t.no_data, &mut o, &[t.module, t.count], &rows);
            for (title, blocked) in [(t.log_active_list, false), (t.log_blocked_list, true)] {
                let _ = writeln!(o, "### {}\n", esc(title));
                let rows: Vec<Vec<String>> = c
                    .log
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
                            c.m(&c.ts(&r.time)),
                            c.m(&r.method),
                            c.m(&crate::ftext::log_text(&r.url, c.o.lang)),
                            r.status.map(|s| s.to_string()).unwrap_or_default(),
                            c.m(&crate::ftext::log_size_type(
                                r.bytes,
                                r.ctype.as_deref(),
                                c.o.lang,
                            )),
                            c.m(&r.module),
                            c.m(&crate::ftext::log_error_cell(
                                r.note.as_deref(),
                                r.error.as_deref(),
                                c.o.lang,
                            )),
                        ]
                    })
                    .collect();
                if rows.is_empty() {
                    let _ = writeln!(o, "*{}*\n", esc(t.no_data));
                } else {
                    md_table(
                        c.t.no_data,
                        &mut o,
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
                    );
                }
            }
        }
    }
    if s.appx {
        let _ = writeln!(
            o,
            "## {}\n\n### {}\n\n{}\n",
            esc(t.appx),
            esc(t.method_title),
            esc(t.method_text)
        );
        if let Some(i18n::IncompleteTable { title, head, rows }) =
            i18n::incomplete_sources(c.o.lang, &snap.scans)
        {
            let _ = writeln!(o, "### {}\n", esc(title));
            let rows: Vec<Vec<String>> = rows
                .iter()
                .map(|[id, why]| vec![format!("`{id}`"), esc(why)])
                .collect();
            md_table(c.t.no_data, &mut o, &head, &rows);
        }
        let secrets: Vec<_> = snap.secrets.iter().filter(|s| s.kind != "host").collect();
        if !secrets.is_empty() {
            let _ = writeln!(o, "### {}\n", esc(t.secret));
            let rows: Vec<Vec<String>> = secrets
                .iter()
                .map(|s| {
                    vec![
                        c.m(&s.kind),
                        c.m(&c.doc_name(s.doc)),
                        c.m(&s.location),
                        esc(&c.red.mask(s.value.expose())),
                    ]
                })
                .collect();
            md_table(
                c.t.no_data,
                &mut o,
                &[t.kind, t.file, t.path, t.secret],
                &rows,
            );
        }
        if !snap.scans.is_empty() {
            let _ = writeln!(o, "### {}\n", esc(t.scans));
            let rows: Vec<Vec<String>> = snap
                .scans
                .iter()
                .map(|s| {
                    let profile = if s.profile.is_empty() {
                        &s.profile_id
                    } else {
                        &s.profile
                    };
                    vec![
                        c.m(&s.id),
                        c.m(profile),
                        c.m(&c.ts(&s.started_at)),
                        c.m(&c.ts(s.finished_at.as_deref().unwrap_or(""))),
                        c.m(&s.egress),
                        c.m(&s.status),
                    ]
                })
                .collect();
            md_table(
                c.t.no_data,
                &mut o,
                &["ID", t.profile, t.started, t.finished, t.egress, t.status],
                &rows,
            );
        }
        let _ = writeln!(o, "### {}\n", esc(t.report_params));
        let min = c.o.min_sev.map(|s| c.sev(s)).unwrap_or(t.all);
        for (k, v) in [
            (t.only_confirmed, c.yes_no(c.o.confirmed)),
            (t.min_sev, min),
            (t.picked_only, c.yes_no(c.o.picked_only)),
            (t.secrets_mode, c.secret_mode()),
        ] {
            let _ = writeln!(o, "- **{}:** {}", esc(k), esc(v));
        }
        o.push('\n');
    }
    if c.o.custody {
        crate::sections::custody::render_md(c, &mut o);
    }
    let _ = writeln!(
        o,
        "---\n*{} {} · {}*",
        esc(t.generator),
        esc(crate::GENERATOR),
        esc(&c.date())
    );
    o
}

/// Text form of the diagrams: layers of the graph, the network tree as a nested list, the
/// chronology as a year × lane table and the activity summary.
fn visuals(c: &Ctx, o: &mut String) {
    use crate::svg::{flat, graph, netmap, timeline};
    let l = c.o.lang;
    let v = i18n::viz(l);
    let names = |list: &mut dyn Iterator<Item = String>, max: usize| {
        let all: Vec<String> = list.collect();
        let mut s = all
            .iter()
            .take(max)
            .map(|x| esc(&flat(x)))
            .collect::<Vec<_>>()
            .join(", ");
        if all.len() > max {
            let _ = write!(s, " (+{})", all.len() - max);
        }
        s
    };
    if let Some(m) = graph::model(&c.vis.graph, l) {
        let _ = writeln!(o, "## {}\n", esc(v.graph));
        for (layer, ids) in &m.layers {
            let count: usize = ids.iter().map(|&i| m.nodes[i].members.len().max(1)).sum();
            let mut it = ids.iter().flat_map(|&i| {
                let n = &m.nodes[i];
                if n.members.is_empty() {
                    vec![n.label.clone()]
                } else {
                    n.members.clone()
                }
            });
            let _ = writeln!(
                o,
                "- **{}** ({count}): {}",
                esc(v.layers[*layer]),
                names(&mut it, 12)
            );
        }
        let _ = writeln!(
            o,
            "\n{}: {}. {}\n",
            esc(v.links),
            m.total_edges,
            esc(v.see_html)
        );
    }
    let rows = netmap::rows(&c.vis.netmap);
    if !rows.is_empty() {
        let _ = writeln!(o, "## {}\n", esc(v.netmap));
        for r in &rows {
            let pad = "  ".repeat(r.depth);
            match r.kind {
                Some(k) => {
                    let role = r
                        .role
                        .map(|x| format!(": {}", esc(v.roles[x as usize])))
                        .unwrap_or_default();
                    let _ = writeln!(
                        o,
                        "{pad}- {}: {}{role}",
                        esc(v.net_kinds[k as usize]),
                        esc(&flat(&r.label))
                    );
                }
                None => {
                    let _ = writeln!(
                        o,
                        "{pad}- {}",
                        esc(&netmap::more_label(v.more, l, r.hidden.len()))
                    );
                }
            }
        }
        o.push('\n');
    }
    if let Some(g) = timeline::grid(&c.vis.timeline) {
        let _ = writeln!(o, "## {}\n", esc(v.timeline));
        let mut head = vec![v.year];
        head.extend(g.lanes.iter().map(|x| v.lanes[*x as usize]));
        let rows: Vec<Vec<String>> = g
            .rows
            .iter()
            .map(|(y, folded, cells)| {
                let mut r = vec![if *folded {
                    format!("≤{y}")
                } else {
                    y.to_string()
                }];
                r.extend(cells.iter().map(|cell| {
                    if cell.count == 0 {
                        String::new()
                    } else {
                        let mut it = cell.labels.iter().map(|x| x.0.clone());
                        format!("{} - {}", cell.count, names(&mut it, 3))
                    }
                }));
                r
            })
            .collect();
        md_table(c.t.no_data, o, &head, &rows);
    }
    if let Some(a) = c.vis.activity.norm() {
        let _ = writeln!(o, "## {}\n", esc(v.activity));
        let mut head = vec![""];
        head.extend(v.weekdays.iter());
        let row = std::iter::once(esc(v.total))
            .chain(a.weekdays.iter().map(|x| x.to_string()))
            .collect();
        md_table(c.t.no_data, o, &head, &[row]);
        let hours = a
            .hours
            .iter()
            .enumerate()
            .filter(|(_, n)| **n > 0)
            .map(|(h, n)| format!("{h:02}: {n}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(o, "- {}: {hours}", esc(v.hour));
        let _ = writeln!(
            o,
            "- {} ({} {:02}-{:02}): {} / {}",
            esc(v.off_hours),
            esc(v.work_hours),
            a.start,
            a.end,
            a.off,
            a.total
        );
        if let Some(tz) = c
            .vis
            .activity
            .tz
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            let _ = writeln!(o, "- {}: {}", esc(v.tz), esc(&flat(tz)));
        }
        let _ = writeln!(o, "\n{}\n", esc(v.see_html));
    }
}

/// Optional AI-assisted executive summary: labelled, escaped, secrets masked.
fn ai_summary(c: &Ctx, o: &mut String) {
    let Some(a) = c.ai_summary() else { return };
    let _ = writeln!(o, "## {}\n", esc(i18n::ai_summary_title(c.o.lang)));
    let _ = writeln!(o, "> {}\n", esc(&c.ai_summary_note(a)));
    let mut prev_item = false;
    for b in crate::ai_blocks(&a.text) {
        let item = matches!(b, crate::AiBlock::Item(_));
        if prev_item && !item {
            o.push('\n');
        }
        prev_item = item;
        match b {
            crate::AiBlock::Head(t) => {
                let _ = writeln!(o, "### {}\n", c.m(&t));
            }
            crate::AiBlock::Item(t) => {
                // Numbered items keep their number ("1. …"), which is already list syntax.
                let numbered = t.starts_with(|ch: char| ch.is_ascii_digit());
                let _ = writeln!(o, "{}{}", if numbered { "" } else { "- " }, c.m(&t));
            }
            crate::AiBlock::Para(t) => {
                let _ = writeln!(o, "{}\n", c.m(&t));
            }
        }
    }
    if prev_item {
        o.push('\n');
    }
}

fn summary(c: &Ctx, o: &mut String) {
    let t = c.t;
    let _ = writeln!(o, "## {}\n", esc(t.summary));
    let _ = writeln!(
        o,
        "**{}: {}** ({}): {}\n",
        esc(t.risk),
        c.res
            .risk
            .map(|r| format!("{r}/100"))
            .unwrap_or_else(|| "-".into()),
        esc(i18n::risk_level(c.o.lang, &c.res.risk_level)),
        esc(t.risk_by)
    );
    let rows: Vec<Vec<String>> = SEV_ORDER
        .iter()
        .map(|s| vec![esc(c.sev(*s)), c.res.counts.get(*s).to_string()])
        .collect();
    md_table(c.t.no_data, o, &[t.sev, t.count], &rows);
    if !c.fixed.is_empty() {
        let _ = writeln!(o, "{}: **{}**\n", esc(t.summary_fixed), c.fixed.len());
    }
    if let Some(n) = c.oos_caveat() {
        let _ = writeln!(o, "> {}\n", esc(&n));
    }
    let ov = &c.ov;
    let _ = writeln!(o, "### {}\n", esc(t.docs_by_type));
    let rows: Vec<Vec<String>> = ov
        .docs_by_type
        .iter()
        .map(|(e, n)| vec![c.m(e), n.to_string()])
        .collect();
    md_table(c.t.no_data, o, &[t.kind, t.count], &rows);
    let _ = writeln!(o, "### {}\n", esc(t.top_people));
    let rows: Vec<Vec<String>> = ov
        .top_people
        .iter()
        .map(|(l, n, d)| vec![c.m(l), c.m(n), d.to_string()])
        .collect();
    md_table(c.t.no_data, o, &[t.login, t.name, t.n_docs], &rows);
    let _ = writeln!(o, "### {}\n", esc(t.top_software));
    let rows: Vec<Vec<String>> = ov
        .top_software
        .iter()
        .map(|(n, d)| vec![c.m(n), d.to_string()])
        .collect();
    md_table(c.t.no_data, o, &[t.software, t.n_docs], &rows);
    if !ov.host_software.is_empty() {
        let _ = writeln!(o, "### {}\n", esc(t.host_software));
        let rows: Vec<Vec<String>> = ov
            .host_software
            .iter()
            .map(|(n, k)| vec![c.m(n), k.to_string()])
            .collect();
        md_table(c.t.no_data, o, &[t.software, t.n_hosts], &rows);
    }
    let _ = writeln!(o, "### {}\n", esc(t.eol_software));
    let rows: Vec<Vec<String>> = ov
        .eol_software
        .iter()
        .map(|(n, d, cve)| {
            vec![
                c.m(n),
                c.m(&crate::data::eol_label(d, c.o.lang)),
                cve.map_or_else(|| "-".into(), |x| x.to_string()),
            ]
        })
        .collect();
    md_table(c.t.no_data, o, &[t.software, t.eol, t.cve], &rows);
    let _ = writeln!(o, "### {}\n", esc(t.infra_found));
    let rows = vec![
        vec![esc(t.hosts), ov.hosts.to_string()],
        vec![esc(t.internal), ov.hosts_internal.to_string()],
        vec![esc(t.pcs), ov.pcs.to_string()],
        vec![esc(t.printers), ov.printers.to_string()],
        vec![esc(t.paths), ov.paths.to_string()],
        vec![esc(t.emails), ov.emails.to_string()],
    ];
    md_table(c.t.no_data, o, &[t.kind, t.count], &rows);
}

fn scope(c: &Ctx, o: &mut String) {
    let t = c.t;
    let sc = &c.snap.scope;
    let _ = writeln!(o, "## {}\n", esc(t.scope));
    let mut rows = vec![
        vec![esc(t.client), c.m(&sc.client)],
        vec![esc(t.contact), c.m(&sc.contact)],
    ];
    // The engagement basis is an optional authorization note; the line is omitted when empty.
    if !sc.basis.trim().is_empty() {
        rows.push(vec![esc(t.basis), c.m(&sc.basis)]);
    }
    md_table(c.t.no_data, o, &["", ""], &rows);
    let rows: Vec<Vec<String>> = sc
        .targets
        .iter()
        .map(|x| vec![c.m(&x.v), c.m(&x.kind)])
        .collect();
    md_table(c.t.no_data, o, &[t.targets, t.kind], &rows);
    let (title, list) = (t.excl, &sc.excl);
    {
        if !list.is_empty() {
            let _ = writeln!(
                o,
                "**{}:** {}\n",
                esc(title),
                list.iter().map(|x| c.m(x)).collect::<Vec<_>>().join(", ")
            );
        }
    }
}

fn card(c: &Ctx, o: &mut String, f: &Finding) {
    let t = c.t;
    let _ = writeln!(
        o,
        "### {} · {} - {}\n",
        c.fref(f),
        c.m(&f.title),
        esc(c.sev(f.sev))
    );
    let mut meta = vec![
        format!("**{}:** {}", esc(t.status), esc(c.status(f.status))),
        format!("**{}:** {}", esc(t.host), c.m(&f.host)),
    ];
    if !f.category.is_empty() {
        meta.push(format!("**{}:** {}", esc(t.category), c.m(&f.category)));
    }
    if !f.cve.is_empty() {
        meta.push(c.m(&f.cve.join(", ")));
    }
    if !f.mitre.is_empty() {
        meta.push(format!("**{}:** {}", esc(t.mitre), c.m(&f.mitre)));
    }
    let _ = writeln!(o, "{}\n", meta.join(" · "));
    if !f.description.is_empty() {
        let _ = writeln!(o, "**{}.** {}\n", esc(t.description), c.m(&f.description));
    }
    if !f.evidence.is_empty() {
        let _ = writeln!(
            o,
            "**{}:**\n\n{}\n",
            esc(t.evidence),
            md_code_block(&c.r(&f.evidence))
        );
    }
    if let Some(u) = f.url.as_deref().filter(|u| !u.is_empty()) {
        // No autolink: an address in `<…>` must stay plain text.
        let _ = writeln!(o, "**{}:** {}\n", esc(t.url), c.m(u));
    }
    if !f.recommendation.is_empty() {
        let _ = writeln!(
            o,
            "**{}.** {}\n",
            esc(t.recommendation),
            c.m(&f.recommendation)
        );
    }
    let p = &f.provenance;
    let mut parts = Vec::new();
    if !p.rule.is_empty() {
        parts.push(format!("{} {}", esc(t.rule), c.m(&p.rule)));
    }
    if !p.docs.is_empty() {
        let docs: Vec<String> = p.docs.iter().map(|d| c.doc_name(*d)).collect();
        parts.push(format!("{}: {}", esc(t.source_docs), c.m(&docs.join(", "))));
    }
    if !parts.is_empty() {
        let _ = writeln!(o, "*{}: {}*\n", esc(t.provenance), parts.join("; "));
    }
}
