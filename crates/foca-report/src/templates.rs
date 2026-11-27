//! Additional report templates: `executive` (one page for management), `compliance` (КСЗІ /
//! standards) and `lab` (laboratory work). Each template builds a small document model that is
//! rendered to HTML (same CSP and print stylesheet as the full report) or Markdown; every
//! string from data is masked (`Ctx::r`) before rendering and escaped by the renderer.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use foca_analysis::standards::{
    is_cwe_top25, RuleStandards, Standards, ATTACK_VERSION, NDTZI_3_6_006, OWASP_TOP10,
};
use foca_core::api::Finding;
use foca_core::Severity;

use crate::data::sev_id;
use crate::i18n::{self, TplText};
use crate::opts::Template;
use crate::safe::{html as esc, md as mesc, yaml_str};
use crate::Ctx;

/// A cell or paragraph: plain text, optionally styled as a severity badge.
pub(crate) enum Cell {
    Text(String),
    Badge(Severity, String),
}

pub(crate) enum Block {
    H2(String),
    P(String),
    Lead(String),
    Risk {
        score: String,
        level: String,
        lvl: String,
        label: String,
    },
    List(Vec<String>),
    OList(Vec<String>),
    Kv(Vec<(String, String)>),
    Table {
        head: Vec<String>,
        rows: Vec<Vec<Cell>>,
        num: Vec<usize>,
    },
    Note(String, String),
    Sign(Vec<(String, String)>),
}

/// Extra styles of these templates; the shared stylesheet stays untouched so the full report
/// is byte-for-byte the same.
const EXTRA_CSS: &str = ".lead { font-size: 11.5pt; color: var(--muted); }\n\
.disclaimer { border: 1px solid var(--line); border-left: 4px solid var(--warn); border-radius: 6px; padding: 8px 12px; margin: 1em 0; font-size: 9.5pt; }\n\
.sign { display: grid; grid-template-columns: 40mm 1fr; gap: 14px 12px; margin-top: 2em; }\n\
.sign dd { margin: 0; border-bottom: 1px solid var(--ink); min-height: 1.4em; }\n\
.sign dd small { display: block; color: var(--muted); font-size: 8pt; padding-top: 1.6em; }\n\
.onepage { break-inside: avoid-page; }\n";

/// Finding groups for plain-language explanations (index into `TplText::groups`).
fn group(rule: &str) -> usize {
    let r = rule;
    if r == "secret"
        || r == "doc.links"
        || r.contains("password")
        || r == "recon.js_secret"
        || r.ends_with("_secret")
    {
        0
    } else if matches!(
        r,
        "doc.bad_redaction"
            | "doc.pdf_removed_text"
            | "doc.hidden_content"
            | "revisions"
            | "pdf-revisions"
            | "hidden-sheets"
            | "thumbnail"
            | "doc.pdf_revision_authors"
    ) {
        1
    } else if r == "doc.modified_after_signing" || r.starts_with("doc.signature") {
        2
    } else if matches!(
        r,
        "pii" | "gps" | "pim.contact_pii" | "doc.signer_identity" | "mass-names"
    ) {
        3
    } else if r.starts_with("internal-")
        || r.starts_with("doc.lnk_")
        || r.starts_with("mail.")
        || r.starts_with("net.")
        || matches!(
            r,
            "remote-file"
                | "doc.data_connection"
                | "service-accounts"
                | "media.device_serial"
                | "org.structure"
        )
    {
        4
    } else if r.starts_with("eol-")
        || matches!(
            r,
            "sw.kev"
                | "ports-outdated"
                | "recon.outdated_tech"
                | "recon.vuln_js_lib"
                | "internetdb-cve"
        )
    {
        5
    } else if r.starts_with("infra.tls")
        || r.starts_with("infra.cert")
        || r.starts_with("recon.web.hsts")
    {
        6
    } else if r.starts_with("recon.")
        || r.starts_with("fuzz-")
        || r == "dangling-cname"
        || r.starts_with("infra.")
    {
        7
    } else {
        8
    }
}

fn fill(tpl: &str, args: &[&str]) -> String {
    let mut s = tpl.to_string();
    for (i, a) in args.iter().enumerate() {
        s = s.replace(&format!("{{{i}}}"), a);
    }
    s
}

fn join(v: &[String]) -> String {
    if v.is_empty() {
        "-".into()
    } else {
        v.join(", ")
    }
}

/// Mapping of a finding: the rule's standards, with the ATT&CK technique the finding itself
/// carries when the rule has none in the file.
fn mapping(f: &Finding) -> RuleStandards {
    let mut m = Standards::builtin()
        .for_rule(&f.provenance.rule)
        .cloned()
        .unwrap_or_default();
    if m.mitre.is_empty() {
        if let Some(t) = f
            .mitre
            .split_whitespace()
            .next()
            .filter(|t| t.starts_with('T'))
        {
            m.mitre.push(t.to_string());
        }
    }
    m
}

fn risk_block(c: &Ctx) -> Block {
    let lvl = c.res.risk_level.clone();
    Block::Risk {
        score: c
            .res
            .risk
            .map(|r| r.to_string())
            .unwrap_or_else(|| "-".into()),
        level: i18n::risk_level(c.o.lang, &lvl).to_string(),
        lvl,
        label: c.t.risk.to_string(),
    }
}

/// Distinct groups of the selected findings, most severe first.
fn groups_by_severity(c: &Ctx) -> Vec<usize> {
    let mut out = Vec::new();
    for f in &c.main {
        let g = group(&f.provenance.rule);
        if !out.contains(&g) {
            out.push(g);
        }
    }
    out
}

fn actions(c: &Ctx, tt: &TplText, n: usize) -> Vec<String> {
    let mut out: Vec<String> = groups_by_severity(c)
        .into_iter()
        .map(|g| tt.groups[g].1.to_string())
        .take(n)
        .collect();
    for a in tt.generic_actions {
        if out.len() >= n {
            break;
        }
        out.push(a.to_string());
    }
    out
}

fn executive(c: &Ctx, tt: &TplText) -> Vec<Block> {
    let mut b = vec![Block::Lead(tt.exec_lead.into()), risk_block(c)];
    let n = c.res.total.to_string();
    let cc =
        c.t.summary_text_c
            .replace("{c}", &c.res.counts.crit.to_string())
            .replace("{h}", &c.res.counts.high.to_string());
    b.push(Block::P(format!("{}: {n}; {cc}.", tt.exec_findings_n)));
    b.push(Block::H2(tt.exec_top.into()));
    if c.main.is_empty() {
        b.push(Block::P(tt.exec_none.into()));
    } else {
        b.push(Block::OList(
            c.main
                .iter()
                .take(5)
                .map(|f| {
                    format!(
                        "{}: {} - {}",
                        c.sev(f.sev),
                        c.r(&f.title),
                        tt.groups[group(&f.provenance.rule)].0
                    )
                })
                .collect(),
        ));
    }
    b.push(Block::H2(tt.exec_actions.into()));
    b.push(Block::OList(actions(c, tt, 3)));
    ai_summary(c, &mut b);
    b
}

/// Optional AI-assisted summary at the end of the executive brief (labelled, masked).
fn ai_summary(c: &Ctx, b: &mut Vec<Block>) {
    let Some(a) = c.ai_summary() else { return };
    b.push(Block::H2(i18n::ai_summary_title(c.o.lang).into()));
    b.push(Block::Lead(c.ai_summary_note(a)));
    let mut items = Vec::new();
    for blk in crate::ai_blocks(&a.text) {
        match blk {
            crate::AiBlock::Item(t) => items.push(c.r(&t)),
            crate::AiBlock::Head(t) | crate::AiBlock::Para(t) => {
                if !items.is_empty() {
                    b.push(Block::List(std::mem::take(&mut items)));
                }
                b.push(Block::P(c.r(&t)));
            }
        }
    }
    if !items.is_empty() {
        b.push(Block::List(items));
    }
}

fn standards_table(c: &Ctx, tt: &TplText, wide: bool) -> Block {
    let mut head = vec![
        tt.col_no.to_string(),
        c.t.sev.to_string(),
        tt.col_finding.to_string(),
        format!("MITRE {ATTACK_VERSION}"),
        format!("CWE / {OWASP_TOP10}"),
    ];
    if wide {
        head.push("WSTG v4.2".into());
    }
    head.extend([
        "ISO 27001".to_string(),
        format!("NIST SP 800-53 / {NDTZI_3_6_006}"),
        "НД ТЗІ 2.5-004-99".into(),
        "НД ТЗІ 3.7-003-05".into(),
    ]);
    let rows = c
        .main
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let m = mapping(f);
            let mut cwe: Vec<String> = m
                .cwe
                .iter()
                .map(|c| {
                    if is_cwe_top25(c) {
                        format!("{c} (Top 25)")
                    } else {
                        c.clone()
                    }
                })
                .collect();
            cwe.extend(m.owasp.iter().cloned());
            let mut row = vec![
                Cell::Text((i + 1).to_string()),
                Cell::Badge(f.sev, c.sev(f.sev).to_string()),
                Cell::Text(c.r(&f.title)),
                Cell::Text(join(&m.mitre)),
                Cell::Text(join(&cwe)),
            ];
            if wide {
                row.push(Cell::Text(join(&m.wstg)));
            }
            row.push(Cell::Text(join(&m.iso27001)));
            row.push(Cell::Text(join(&m.nist)));
            row.push(Cell::Text(join(&m.ndtzi)));
            row.push(Cell::Text(join(&m.kszi)));
            row
        })
        .collect();
    Block::Table {
        head,
        rows,
        num: vec![0],
    }
}

fn disclaimer(c: &Ctx, tt: &TplText) -> Block {
    Block::Note(
        tt.comp_disclaimer.into(),
        Standards::builtin().disclaimer.get(c.o.lang.code()).into(),
    )
}

fn compliance(c: &Ctx, tt: &TplText) -> Vec<Block> {
    let st = Standards::builtin();
    let lang = c.o.lang.code();
    let mut b = vec![
        Block::Lead(tt.comp_lead.into()),
        risk_block(c),
        disclaimer(c, tt),
    ];
    b.push(Block::H2(tt.comp_table.into()));
    if c.main.is_empty() {
        b.push(Block::P(c.t.no_data.into()));
    } else {
        b.push(standards_table(c, tt, true));
        b.push(Block::P(tt.comp_legacy.into()));
    }
    let mut nd: BTreeMap<String, u32> = BTreeMap::new();
    let mut iso: BTreeMap<String, u32> = BTreeMap::new();
    let mut ks: BTreeMap<String, u32> = BTreeMap::new();
    let mut ni: BTreeMap<String, u32> = BTreeMap::new();
    // Privacy references keep the order of the mapping file (GDPR first, then the Ukrainian law).
    let mut pv: Vec<(String, u32)> = Vec::new();
    let mut unmapped = 0;
    for f in &c.main {
        let m = mapping(f);
        if m.is_empty() {
            unmapped += 1;
        }
        for x in m.ndtzi {
            *nd.entry(x).or_default() += 1;
        }
        for x in m.iso27001 {
            *iso.entry(x).or_default() += 1;
        }
        for x in m.kszi {
            *ks.entry(x).or_default() += 1;
        }
        for x in m.nist {
            *ni.entry(x).or_default() += 1;
        }
        for x in m.privacy {
            match pv.iter_mut().find(|(k, _)| *k == x) {
                Some((_, n)) => *n += 1,
                None => pv.push((x, 1)),
            }
        }
    }
    let iso_key = |k: &str| {
        let (a, b) = k.split_once('.').unwrap_or((k, "0"));
        (a.parse::<u32>().unwrap_or(0), b.parse::<u32>().unwrap_or(0))
    };
    b.push(Block::H2(tt.comp_nist.into()));
    if ni.is_empty() {
        b.push(Block::P(c.t.no_data.into()));
    } else {
        let rows = ni
            .iter()
            .map(|(k, n)| {
                vec![
                    Cell::Text(k.clone()),
                    Cell::Text(
                        st.nist
                            .get(k)
                            .map(|t| t.get(lang).to_string())
                            .unwrap_or_default(),
                    ),
                    Cell::Text(n.to_string()),
                ]
            })
            .collect();
        b.push(Block::Table {
            head: vec![tt.col_control.into(), c.t.name.into(), tt.col_count.into()],
            rows,
            num: vec![2],
        });
    }
    if !pv.is_empty() {
        b.push(Block::H2(tt.comp_privacy.into()));
        let rows = pv
            .iter()
            .map(|(k, n)| {
                vec![
                    Cell::Text(
                        st.privacy
                            .get(k)
                            .map(|p| p.title(lang).to_string())
                            .unwrap_or_else(|| k.clone()),
                    ),
                    Cell::Text(n.to_string()),
                ]
            })
            .collect();
        b.push(Block::Table {
            head: vec![c.t.name.into(), tt.col_count.into()],
            rows,
            num: vec![1],
        });
    }
    b.push(Block::H2(tt.comp_ndtzi.into()));
    if nd.is_empty() {
        b.push(Block::P(c.t.no_data.into()));
    } else {
        let rows = nd
            .iter()
            .map(|(k, n)| {
                let s = st.ndtzi.get(k);
                vec![
                    Cell::Text(k.clone()),
                    Cell::Text(s.map(|s| s.name(lang).to_string()).unwrap_or_default()),
                    Cell::Text(s.map(|s| s.clause.clone()).unwrap_or_default()),
                    Cell::Text(n.to_string()),
                ]
            })
            .collect();
        b.push(Block::Table {
            head: vec![
                tt.col_code.into(),
                tt.col_service.into(),
                tt.col_clause.into(),
                tt.col_count.into(),
            ],
            rows,
            num: vec![3],
        });
    }
    b.push(Block::H2(tt.comp_iso.into()));
    if iso.is_empty() {
        b.push(Block::P(c.t.no_data.into()));
    } else {
        let mut keys: Vec<_> = iso.iter().collect();
        keys.sort_by_key(|(k, _)| iso_key(k));
        let rows = keys
            .into_iter()
            .map(|(k, n)| {
                vec![
                    Cell::Text(format!("A.{k}")),
                    Cell::Text(st.iso27001.get(k).cloned().unwrap_or_default()),
                    Cell::Text(n.to_string()),
                ]
            })
            .collect();
        b.push(Block::Table {
            head: vec![tt.col_control.into(), c.t.name.into(), tt.col_count.into()],
            rows,
            num: vec![2],
        });
    }
    b.push(Block::H2(tt.comp_kszi.into()));
    if ks.is_empty() {
        b.push(Block::P(c.t.no_data.into()));
    } else {
        let rows = ks
            .iter()
            .map(|(k, n)| {
                vec![
                    Cell::Text(k.clone()),
                    Cell::Text(
                        st.kszi
                            .get(k)
                            .map(|t| t.get(lang).to_string())
                            .unwrap_or_default(),
                    ),
                    Cell::Text(n.to_string()),
                ]
            })
            .collect();
        b.push(Block::Table {
            head: vec![
                tt.col_clause.into(),
                tt.col_stage.into(),
                tt.col_count.into(),
            ],
            rows,
            num: vec![2],
        });
    }
    b.push(Block::P(format!("{}: {unmapped}.", tt.comp_unmapped)));
    b
}

fn lab(c: &Ctx, tt: &TplText) -> Vec<Block> {
    let snap = c.snap;
    let object = if snap.project.domain.is_empty() {
        c.r(&snap.project.name)
    } else {
        c.r(&snap.project.domain)
    };
    let mut b = vec![Block::H2(format!("1. {}", tt.lab_goal))];
    b.push(Block::P(fill(tt.lab_goal_text, &[&object])));

    b.push(Block::H2(format!("2. {}", tt.lab_method)));
    let mut profiles: Vec<String> = Vec::new();
    for s in &snap.scans {
        let p = c.r(&s.profile);
        if !p.is_empty() && !profiles.contains(&p) {
            profiles.push(p);
        }
    }
    let mut sources: Vec<String> = Vec::new();
    for f in &snap.findings {
        let s = c.r(&i18n::source_label(&f.source, c.o.lang));
        if !s.is_empty() && !sources.contains(&s) {
            sources.push(s);
        }
    }
    sources.sort();
    b.push(Block::Kv(vec![
        (tt.lab_profile.into(), join(&profiles)),
        (tt.lab_sources.into(), join(&sources)),
        (tt.lab_tool.into(), crate::GENERATOR.into()),
        (tt.lab_requests.into(), c.ls.total.to_string()),
        (tt.lab_limits.into(), tt.lab_limits_text.into()),
    ]));

    b.push(Block::H2(format!("3. {}", tt.lab_input)));
    let targets: Vec<String> = snap.scope.targets.iter().map(|t| c.r(&t.v)).collect();
    b.push(Block::Kv(vec![
        (tt.lab_object.into(), c.r(&snap.project.name)),
        (c.t.client.into(), c.r(&snap.scope.client)),
        (tt.lab_targets.into(), join(&targets)),
        (
            c.t.excl.into(),
            join(&snap.scope.excl.iter().map(|x| c.r(x)).collect::<Vec<_>>()),
        ),
        (c.t.date.into(), c.date()),
    ]));

    b.push(Block::H2(format!("4. {}", tt.lab_course)));
    let ov = &c.ov;
    let k = &c.res.counts;
    let s = |n: u32| n.to_string();
    b.push(Block::OList(vec![
        fill(
            tt.lab_stage_docs,
            &[&s(ov.docs_total), &s(ov.docs_analyzed)],
        ),
        fill(
            tt.lab_stage_meta,
            &[&s(ov.people), &s(ov.emails), &s(ov.hosts), &s(ov.software)],
        ),
        fill(
            tt.lab_stage_analysis,
            &[
                &s(c.res.total),
                &s(k.crit),
                &s(k.high),
                &s(k.warn),
                &s(k.low),
                &s(k.info),
            ],
        ),
        fill(
            tt.lab_stage_net,
            &[&s(c.ls.total), &s(c.ls.passive), &s(c.ls.active)],
        ),
    ]));

    b.push(Block::H2(format!("5. {}", tt.lab_table)));
    if c.main.is_empty() {
        b.push(Block::P(c.t.no_data.into()));
    } else {
        b.push(standards_table(c, tt, false));
        b.push(Block::P(tt.comp_legacy.into()));
    }

    b.push(Block::H2(format!("6. {}", tt.lab_conclusions)));
    let lvl = i18n::risk_level(c.o.lang, &c.res.risk_level);
    let score = c
        .res
        .risk
        .map(|r| r.to_string())
        .unwrap_or_else(|| "-".into());
    b.push(Block::P(fill(
        tt.lab_conclusion_risk,
        &[lvl, &score, &s(c.res.total)],
    )));
    let mut findings_text: Vec<String> = groups_by_severity(c)
        .into_iter()
        .map(|g| tt.groups[g].0.to_string())
        .collect();
    if findings_text.is_empty() {
        findings_text.push(tt.exec_none.into());
    }
    b.push(Block::List(findings_text));
    b.push(Block::OList(actions(c, tt, 5)));
    b.push(disclaimer(c, tt));
    b.push(Block::Sign(vec![
        (tt.lab_done_by.into(), tt.lab_signature.into()),
        (tt.lab_checked_by.into(), tt.lab_signature.into()),
    ]));
    b
}

pub(crate) fn blocks(c: &Ctx) -> (String, Vec<Block>) {
    let tt = i18n::tpl_text(c.o.lang);
    match c.o.tpl {
        Template::Executive => (tt.exec_title.into(), executive(c, tt)),
        Template::Compliance => (tt.comp_title.into(), compliance(c, tt)),
        _ => (tt.lab_title.into(), lab(c, tt)),
    }
}

fn cell_html(x: &Cell) -> String {
    match x {
        Cell::Text(s) => esc(s),
        Cell::Badge(sev, s) => format!("<span class=\"badge {}\">{}</span>", sev_id(*sev), esc(s)),
    }
}

pub(crate) fn render_html(c: &Ctx) -> String {
    let (kind, body) = blocks(c);
    let mut h = String::with_capacity(32 * 1024);
    let title = format!("{kind}: {}", c.r(&c.snap.project.name));
    let _ = write!(
        h,
        "<!DOCTYPE html>\n<html lang=\"{}\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{}\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"generator\" content=\"{}\">\n<meta name=\"referrer\" content=\"no-referrer\">\n\
         <title>{}</title>\n<style>\n{}{EXTRA_CSS}</style>\n</head>\n<body class=\"tpl-{}\">\n",
        c.o.lang.code(),
        crate::page::CSP,
        esc(crate::GENERATOR),
        esc(&title),
        crate::page::CSS,
        c.o.tpl.id()
    );
    let _ = writeln!(
        h,
        "<header class=\"head-data\"><h1>{}</h1><div class=\"muted\">{} · {} · {}</div></header>",
        esc(&kind),
        esc(&c.r(&c.snap.project.name)),
        esc(&c.r(&c.snap.scope.client)),
        esc(&c.date())
    );
    if c.o.tpl == Template::Executive {
        h.push_str("<div class=\"onepage\">\n");
    } else {
        h.push_str("<div class=\"body\">\n");
    }
    for blk in &body {
        match blk {
            Block::H2(s) => {
                let _ = writeln!(h, "<h2>{}</h2>", esc(s));
            }
            Block::P(s) => {
                let _ = writeln!(h, "<p>{}</p>", esc(s));
            }
            Block::Lead(s) => {
                let _ = writeln!(h, "<p class=\"lead\">{}</p>", esc(s));
            }
            Block::Risk {
                score,
                level,
                lvl,
                label,
            } => {
                let lvl: String = lvl.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
                let _ = writeln!(
                    h,
                    "<div class=\"riskbox\"><div class=\"risk {lvl}\"><div class=\"s\">{}</div>\
                     <div class=\"n\">{}<small>/100</small></div><div class=\"l\">{}</div></div></div>",
                    esc(label),
                    esc(score),
                    esc(level)
                );
            }
            Block::List(v) | Block::OList(v) => {
                let tag = if matches!(blk, Block::List(_)) {
                    "ul"
                } else {
                    "ol"
                };
                let _ = write!(h, "<{tag}>");
                for x in v {
                    let _ = write!(h, "<li>{}</li>", esc(x));
                }
                let _ = writeln!(h, "</{tag}>");
            }
            Block::Kv(v) => {
                h.push_str("<dl class=\"kv\">");
                for (k, x) in v {
                    let x = if x.is_empty() { "-" } else { x.as_str() };
                    let _ = write!(h, "<dt>{}</dt><dd>{}</dd>", esc(k), esc(x));
                }
                h.push_str("</dl>\n");
            }
            Block::Table { head, rows, num } => {
                let head: Vec<&str> = head.iter().map(String::as_str).collect();
                let rows: Vec<Vec<String>> = rows
                    .iter()
                    .map(|r| r.iter().map(cell_html).collect())
                    .collect();
                crate::table::html_table(&mut h, &head, &rows, num);
            }
            Block::Note(t, s) => {
                let _ = writeln!(
                    h,
                    "<div class=\"disclaimer\"><b>{}.</b> {}</div>",
                    esc(t),
                    esc(s)
                );
            }
            Block::Sign(v) => {
                h.push_str("<dl class=\"sign\">");
                for (k, hint) in v {
                    let _ = write!(
                        h,
                        "<dt>{}</dt><dd><small>{}</small></dd>",
                        esc(k),
                        esc(hint)
                    );
                }
                h.push_str("</dl>\n");
            }
        }
    }
    if c.o.custody {
        crate::sections::custody::render_html(c, &mut h);
    }
    let credits = c
        .data_credits()
        .map(|x| format!("<span>{}</span>", esc(x)))
        .unwrap_or_default();
    let _ = write!(
        h,
        "</div>\n<footer class=\"gen\"><span>{} {} · {}</span>{credits}<span>{}</span></footer>\n</body>\n</html>\n",
        esc(c.t.generator),
        esc(crate::GENERATOR),
        esc(&c.date()),
        esc(c.t.conf)
    );
    h
}

fn cell_md(x: &Cell) -> String {
    match x {
        Cell::Text(s) | Cell::Badge(_, s) => mesc(s),
    }
}

pub(crate) fn render_md(c: &Ctx) -> String {
    let (kind, body) = blocks(c);
    let mut o = String::with_capacity(16 * 1024);
    o.push_str("---\n");
    let _ = writeln!(
        o,
        "title: {}",
        yaml_str(&format!("{kind}: {}", c.r(&c.snap.project.name)))
    );
    let _ = writeln!(o, "project: {}", yaml_str(&c.r(&c.snap.project.name)));
    let _ = writeln!(o, "client: {}", yaml_str(&c.r(&c.snap.scope.client)));
    let _ = writeln!(o, "date: {}", c.iso_date());
    let _ = writeln!(o, "template: {}", c.o.tpl.id());
    let _ = writeln!(o, "lang: {}", c.o.lang.code());
    match c.res.risk {
        Some(r) => {
            let _ = writeln!(o, "risk: {r}");
        }
        None => o.push_str("risk: null\n"),
    }
    let _ = writeln!(o, "findings: {}", c.res.total);
    o.push_str("---\n\n");
    let _ = writeln!(o, "# {}\n", mesc(&kind));
    let _ = writeln!(
        o,
        "{} · {} · {}\n",
        mesc(&c.r(&c.snap.project.name)),
        mesc(&c.r(&c.snap.scope.client)),
        mesc(&c.date())
    );
    for blk in &body {
        match blk {
            Block::H2(s) => {
                let _ = writeln!(o, "## {}\n", mesc(s));
            }
            Block::P(s) => {
                let _ = writeln!(o, "{}\n", mesc(s));
            }
            Block::Lead(s) => {
                let _ = writeln!(o, "*{}*\n", mesc(s));
            }
            Block::Risk {
                score,
                level,
                label,
                ..
            } => {
                let _ = writeln!(
                    o,
                    "**{}: {}/100 - {}**\n",
                    mesc(label),
                    mesc(score),
                    mesc(level)
                );
            }
            Block::List(v) => {
                for x in v {
                    let _ = writeln!(o, "- {}", mesc(x));
                }
                o.push('\n');
            }
            Block::OList(v) => {
                for (i, x) in v.iter().enumerate() {
                    let _ = writeln!(o, "{}. {}", i + 1, mesc(x));
                }
                o.push('\n');
            }
            Block::Kv(v) => {
                for (k, x) in v {
                    let x = if x.is_empty() { "-" } else { x.as_str() };
                    let _ = writeln!(o, "- **{}:** {}", mesc(k), mesc(x));
                }
                o.push('\n');
            }
            Block::Table { head, rows, .. } => {
                let head: Vec<&str> = head.iter().map(String::as_str).collect();
                let rows: Vec<Vec<String>> = rows
                    .iter()
                    .map(|r| r.iter().map(cell_md).collect())
                    .collect();
                crate::table::md_table(c.t.no_data, &mut o, &head, &rows);
            }
            Block::Note(t, s) => {
                let _ = writeln!(o, "> **{}.** {}\n", mesc(t), mesc(s));
            }
            Block::Sign(v) => {
                for (k, hint) in v {
                    let _ = writeln!(
                        o,
                        "**{}:** ______________________ ({})\n",
                        mesc(k),
                        mesc(hint)
                    );
                }
            }
        }
    }
    if c.o.custody {
        crate::sections::custody::render_md(c, &mut o);
    }
    let _ = writeln!(
        o,
        "---\n\n{} {} · {}",
        mesc(c.t.generator),
        mesc(crate::GENERATOR),
        mesc(&c.date())
    );
    if let Some(x) = c.data_credits() {
        let _ = writeln!(o, "\n{}", mesc(x));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_cover_known_rules() {
        assert_eq!(group("secret"), 0);
        assert_eq!(group("rdp-password"), 0);
        assert_eq!(group("doc.bad_redaction"), 1);
        assert_eq!(group("doc.signature_digest_mismatch"), 2);
        assert_eq!(group("gps"), 3);
        assert_eq!(group("doc.lnk_unc_path"), 4);
        assert_eq!(group("sw.kev"), 5);
        assert_eq!(group("infra.tls_legacy_version"), 6);
        assert_eq!(group("fuzz-git"), 7);
        assert_eq!(group("whatever"), 8);
    }

    #[test]
    fn fill_replaces_positional_args() {
        assert_eq!(fill("{0} and {1}", &["a", "b"]), "a and b");
    }
}
