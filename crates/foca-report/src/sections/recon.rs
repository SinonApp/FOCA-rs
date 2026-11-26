//! Website and technologies section (part of the infrastructure section): site recon from
//! `snapshot.recon` (`ReconView`, docs/API.md). Secrets are masks only (the snapshot holds no
//! values), and every string also goes through the report redactor (`Ctx::h` / `Ctx::m` /
//! `Ctx::r`).

use std::fmt::Write as _;

use serde_json::{json, Value};

use crate::i18n::{recon_strings, ReconT};
use crate::recon_view::{ReconView, Tech};
use crate::safe::{html as esc, md as mesc};
use crate::Ctx;

/// Maximum number of rows shown for long lists.
const MAX_ROWS: usize = 30;

fn bucket_state(t: &ReconT, s: &str) -> &'static str {
    match s {
        "public" => t.b_public,
        "closed" => t.b_closed,
        "not_found" => t.b_not_found,
        "unchecked" => t.b_unchecked,
        _ => t.b_unknown,
    }
}

fn tech_state(t: &ReconT, x: &Tech, lang: crate::Lang) -> String {
    match (&x.outdated, &x.version) {
        (Some(o), _) => format!("{} - {}", t.outdated, crate::ftext::outdated_note(o, lang)),
        (None, Some(_)) => t.current.to_string(),
        (None, None) => t.unknown_ver.to_string(),
    }
}

fn count(shown: usize, total: usize, t: &ReconT) -> String {
    if total > shown {
        format!(" ({shown} {} {total})", t.of)
    } else {
        String::new()
    }
}

/// HTML: the website and technologies subsection inside the infrastructure section.
pub(crate) fn html(c: &Ctx, h: &mut String) {
    let t = recon_strings(c.o.lang);
    let r = ReconView::from_snapshot(&c.snap.recon);
    if r.is_empty() {
        return;
    }
    let _ = write!(h, "<h3 id=\"webrecon\">{}</h3>", esc(t.title));
    if r.level.as_deref() == Some("external") {
        let _ = write!(h, "<p class=\"muted\">{}</p>", esc(t.via_archive));
    }
    let table = |h: &mut String, head: &[&str], rows: Vec<Vec<String>>| {
        h.push_str("<table><thead><tr>");
        for th in head {
            let _ = write!(h, "<th>{}</th>", esc(th));
        }
        h.push_str("</tr></thead><tbody>\n");
        for row in rows {
            h.push_str("<tr>");
            for td in row {
                let _ = write!(h, "<td>{td}</td>");
            }
            h.push_str("</tr>\n");
        }
        h.push_str("</tbody></table>\n");
    };
    if !r.tech.is_empty() {
        let _ = write!(h, "<h4>{}</h4>", esc(t.tech));
        let rows = r
            .tech
            .iter()
            .map(|x| {
                vec![
                    c.h(&x.name),
                    format!(
                        "<span class=\"mono\">{}</span>",
                        c.h(x.version.as_deref().unwrap_or("-"))
                    ),
                    c.h(&crate::ftext::tech_category(&x.category, c.o.lang)),
                    c.h(&tech_state(t, x, c.o.lang)),
                ]
            })
            .collect();
        table(h, &[t.name, t.version, t.category, t.state], rows);
    }
    for s in &r.sites {
        if let Some(f) = &s.favicon {
            let _ = write!(h, "<h4>{} · {}</h4><ul>", esc(t.favicon), c.h(&s.host));
            let _ = write!(
                h,
                "<li class=\"mono\">mmh3 {} · md5 {}</li>",
                f.mmh3,
                c.h(&f.md5)
            );
            for q in &f.queries {
                let _ = write!(
                    h,
                    "<li>{}: <span class=\"mono\">{}</span></li>",
                    c.h(&q.engine),
                    c.h(&q.q)
                );
            }
            h.push_str("</ul>\n");
        }
    }
    let list = |h: &mut String, title: &str, items: Vec<String>, extra: String| {
        if items.is_empty() {
            return;
        }
        let _ = write!(h, "<h4>{}{}</h4><ul>", esc(title), esc(&extra));
        for i in items {
            let _ = write!(h, "<li>{i}</li>");
        }
        h.push_str("</ul>\n");
    };
    list(
        h,
        t.analytics,
        r.analytics
            .iter()
            .map(|a| {
                format!(
                    "<span class=\"mono\">{}</span> · {}",
                    c.h(&a.id),
                    c.h(&a.kind)
                )
            })
            .collect(),
        String::new(),
    );
    list(
        h,
        t.hidden,
        r.hidden_paths
            .iter()
            .take(MAX_ROWS)
            .map(|p| {
                format!(
                    "<span class=\"mono\">{}</span> · {}",
                    c.h(&p.path),
                    c.h(&p.reason)
                )
            })
            .collect(),
        count(r.hidden_paths.len().min(MAX_ROWS), r.hidden_paths.len(), t),
    );
    list(
        h,
        t.sitemap,
        r.sitemap
            .iter()
            .take(MAX_ROWS)
            .map(|u| format!("<span class=\"mono\">{}</span>", c.h(&u.loc)))
            .collect(),
        count(
            r.sitemap.len().min(MAX_ROWS),
            r.sitemap_total.max(r.sitemap.len()),
            t,
        ),
    );
    list(
        h,
        t.security,
        r.security
            .iter()
            .flat_map(|x| x.contacts.iter().map(|k| c.h(k)))
            .collect(),
        String::new(),
    );
    list(
        h,
        t.endpoints,
        r.endpoints
            .iter()
            .take(MAX_ROWS)
            .map(|e| {
                format!(
                    "<span class=\"mono\">{}{}</span>",
                    e.method
                        .as_deref()
                        .map(|m| format!("{} ", c.h(m)))
                        .unwrap_or_default(),
                    c.h(&e.url)
                )
            })
            .collect(),
        count(
            r.endpoints.len().min(MAX_ROWS),
            r.endpoints_total.max(r.endpoints.len()),
            t,
        ),
    );
    if !r.secrets.is_empty() {
        let _ = write!(
            h,
            "<h4>{}</h4><p class=\"muted\">{}</p>",
            esc(t.secrets),
            esc(t.masked_note)
        );
        let rows = r
            .secrets
            .iter()
            .map(|x| {
                vec![
                    c.h(&x.title),
                    format!("<span class=\"mono\">{}</span>", c.h(&x.mask)),
                    c.h(&x.source),
                ]
            })
            .collect();
        table(h, &[t.name, "mask", t.source], rows);
    }
    if !r.buckets.is_empty() {
        let _ = write!(h, "<h4>{}</h4>", esc(t.buckets));
        let rows = r
            .buckets
            .iter()
            .map(|b| {
                let mut st = bucket_state(t, &b.status).to_string();
                if let Some(k) = b.keys {
                    st.push_str(&format!(" · {k}"));
                }
                vec![
                    format!("<span class=\"mono\">{}</span>", c.h(&b.name)),
                    c.h(&b.label),
                    esc(&st),
                ]
            })
            .collect();
        table(h, &[t.name, t.category, t.state], rows);
    }
    if let Some(code) = r.code.as_ref().filter(|x| !x.hits.is_empty()) {
        list(
            h,
            t.code,
            code.hits
                .iter()
                .take(MAX_ROWS)
                .map(|x| {
                    format!(
                        "{} · <span class=\"mono\">{}</span>",
                        c.h(&x.repo),
                        c.h(&x.path)
                    )
                })
                .collect(),
            count(code.hits.len().min(MAX_ROWS), code.total as usize, t),
        );
    }
}

/// Markdown: the same subsection.
/// DOCX: website technologies (with the archive note), security headers and sitemap counts.
pub(crate) fn doc_tables(c: &Ctx) -> Vec<crate::table::DocTable> {
    let t = recon_strings(c.o.lang);
    let r = ReconView::from_snapshot(&c.snap.recon);
    if r.is_empty() {
        return Vec::new();
    }
    let note = (r.level.as_deref() == Some("external")).then(|| t.via_archive.to_string());
    let rows: Vec<Vec<String>> = r
        .tech
        .iter()
        .map(|x| {
            vec![
                c.r(&x.name),
                c.r(x.version.as_deref().unwrap_or("-")),
                c.r(&crate::ftext::tech_category(&x.category, c.o.lang)),
                c.r(&tech_state(t, x, c.o.lang)),
            ]
        })
        .collect();
    let head = [t.name, t.version, t.category, t.state];
    if rows.is_empty() {
        let mut d = crate::table::DocTable::new(t.title, note, &head, Vec::new());
        d.head.clear();
        return vec![d];
    }
    vec![crate::table::DocTable::new(t.title, note, &head, rows)]
}

pub(crate) fn md(c: &Ctx, o: &mut String) {
    let t = recon_strings(c.o.lang);
    let r = ReconView::from_snapshot(&c.snap.recon);
    if r.is_empty() {
        return;
    }
    let _ = writeln!(o, "### {}\n", mesc(t.title));
    if r.level.as_deref() == Some("external") {
        let _ = writeln!(o, "_{}_\n", mesc(t.via_archive));
    }
    if !r.tech.is_empty() {
        let _ = writeln!(o, "#### {}\n", mesc(t.tech));
        let _ = writeln!(
            o,
            "| {} | {} | {} | {} |\n| --- | --- | --- | --- |",
            mesc(t.name),
            mesc(t.version),
            mesc(t.category),
            mesc(t.state)
        );
        for x in &r.tech {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} |",
                c.m(&x.name),
                c.m(x.version.as_deref().unwrap_or("-")),
                c.m(&crate::ftext::tech_category(&x.category, c.o.lang)),
                c.m(&tech_state(t, x, c.o.lang))
            );
        }
        o.push('\n');
    }
    let list = |o: &mut String, title: &str, items: Vec<String>, extra: String| {
        if items.is_empty() {
            return;
        }
        let _ = writeln!(o, "#### {}{}\n", mesc(title), mesc(&extra));
        for i in items {
            let _ = writeln!(o, "- {i}");
        }
        o.push('\n');
    };
    for s in &r.sites {
        if let Some(f) = &s.favicon {
            let mut items = vec![format!("mmh3 {} · md5 {}", f.mmh3, c.m(&f.md5))];
            items.extend(
                f.queries
                    .iter()
                    .map(|q| format!("{}: {}", c.m(&q.engine), c.m(&q.q))),
            );
            list(
                o,
                &format!("{} · {}", t.favicon, s.host),
                items,
                String::new(),
            );
        }
    }
    list(
        o,
        t.analytics,
        r.analytics
            .iter()
            .map(|a| format!("{} · {}", c.m(&a.id), c.m(&a.kind)))
            .collect(),
        String::new(),
    );
    list(
        o,
        t.hidden,
        r.hidden_paths
            .iter()
            .take(MAX_ROWS)
            .map(|p| format!("{} · {}", c.m(&p.path), c.m(&p.reason)))
            .collect(),
        count(r.hidden_paths.len().min(MAX_ROWS), r.hidden_paths.len(), t),
    );
    list(
        o,
        t.sitemap,
        r.sitemap
            .iter()
            .take(MAX_ROWS)
            .map(|u| c.m(&u.loc))
            .collect(),
        count(
            r.sitemap.len().min(MAX_ROWS),
            r.sitemap_total.max(r.sitemap.len()),
            t,
        ),
    );
    list(
        o,
        t.security,
        r.security
            .iter()
            .flat_map(|x| x.contacts.iter().map(|k| c.m(k)))
            .collect(),
        String::new(),
    );
    list(
        o,
        t.endpoints,
        r.endpoints
            .iter()
            .take(MAX_ROWS)
            .map(|e| c.m(&e.url))
            .collect(),
        count(
            r.endpoints.len().min(MAX_ROWS),
            r.endpoints_total.max(r.endpoints.len()),
            t,
        ),
    );
    if !r.secrets.is_empty() {
        let mut items = vec![format!("_{}_", mesc(t.masked_note))];
        items.extend(
            r.secrets
                .iter()
                .map(|x| format!("{} · {} · {}", c.m(&x.title), c.m(&x.mask), c.m(&x.source))),
        );
        list(o, t.secrets, items, String::new());
    }
    list(
        o,
        t.buckets,
        r.buckets
            .iter()
            .map(|b| {
                format!(
                    "{} · {} · {}",
                    c.m(&b.name),
                    c.m(&b.label),
                    mesc(bucket_state(t, &b.status))
                )
            })
            .collect(),
        String::new(),
    );
    if let Some(code) = &r.code {
        list(
            o,
            t.code,
            code.hits
                .iter()
                .take(MAX_ROWS)
                .map(|x| format!("{} · {}", c.m(&x.repo), c.m(&x.path)))
                .collect(),
            count(code.hits.len().min(MAX_ROWS), code.total as usize, t),
        );
    }
}

/// JSON report: the `website` block (secrets masked; strings then go through the common
/// redactor).
pub(crate) fn json(c: &Ctx) -> Value {
    let r = ReconView::from_snapshot(&c.snap.recon);
    if r.is_empty() {
        return Value::Null;
    }
    json!({
        "at": r.at, "level": r.level,
        "technologies": r.tech.iter().map(|x| json!({ "name": x.name, "version": x.version, "category": x.category, "outdated": x.outdated, "host": x.host })).collect::<Vec<_>>(),
        "favicons": r.sites.iter().filter_map(|s| s.favicon.as_ref().map(|f| json!({ "host": s.host, "url": f.url, "mmh3": f.mmh3, "md5": f.md5,
            "queries": f.queries.iter().map(|q| json!({ "engine": q.engine, "q": q.q })).collect::<Vec<_>>() }))).collect::<Vec<_>>(),
        "analytics": r.analytics.iter().map(|a| json!({ "kind": a.kind, "id": a.id, "host": a.host })).collect::<Vec<_>>(),
        "hidden_paths": r.hidden_paths.iter().map(|p| json!({ "path": p.path, "reason": p.reason, "host": p.host })).collect::<Vec<_>>(),
        "sitemap_total": r.sitemap_total.max(r.sitemap.len()),
        "security_contacts": r.security.iter().flat_map(|x| x.contacts.clone()).collect::<Vec<_>>(),
        "endpoints": r.endpoints.iter().map(|e| json!({ "url": e.url, "method": e.method })).collect::<Vec<_>>(),
        "secrets": r.secrets.iter().map(|x| json!({ "kind": x.kind, "title": x.title, "mask": x.mask, "source": x.source })).collect::<Vec<_>>(),
        "buckets": r.buckets.iter().map(|b| json!({ "name": b.name, "provider": b.label, "status": b.status, "keys": b.keys })).collect::<Vec<_>>(),
        "public_code": r.code.as_ref().map(|x| json!({ "query": x.query, "total": x.total,
            "hits": x.hits.iter().map(|h| json!({ "repo": h.repo, "path": h.path, "url": h.url })).collect::<Vec<_>>() })),
    })
}
