//! Document forensics subsection of the documents section: signatures and
//! qualified certificates, hidden content / redaction / revisions, a personal data summary
//! (types and counts only, never values) and cloud links. Built from the included findings by
//! rule, so triage and severity filters of the report apply here too.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use foca_core::api::Finding;

use crate::safe::{html as esc, md as mesc};
use crate::{Ctx, Lang};

pub use crate::i18n::FxT;

pub fn strings(l: Lang) -> &'static FxT {
    &crate::i18n::bundle(l).forensics
}

/// Localized name of a personal data kind.
pub fn pii_kind(kind: &str, l: Lang) -> &'static str {
    crate::i18n::bundle(l)
        .pii_kind
        .get(kind)
        .map(String::as_str)
        .unwrap_or("-")
}

const SIG_RULES: &[&str] = &[
    "doc.signer_identity",
    "doc.modified_after_signing",
    "doc.signature_digest_mismatch",
    "doc.signature_tsa_gap",
];
const HIDDEN_RULES: &[&str] = &[
    "doc.bad_redaction",
    "doc.hidden_content",
    "doc.pdf_removed_text",
    "doc.pdf_revision_authors",
    "doc.scan_without_text",
];

/// Kind of a `pii` finding: the part of the key after the document, taken from the
/// (Russian) title via the catalog of kinds.
fn pii_kind_of(f: &Finding) -> &'static str {
    const TITLES: &[(&str, &str)] = &[
        ("РНОКПП", "rnokpp"),
        ("ЄДРПОУ", "edrpou"),
        ("IBAN", "iban"),
        ("банковской карты", "card"),
        ("паспорта", "passport"),
        ("ID-карты", "id_card"),
        ("телефона", "phone"),
        ("Гриф", "marking"),
    ];
    TITLES
        .iter()
        .find(|(w, _)| f.title.contains(w))
        .map(|(_, k)| *k)
        .unwrap_or("")
}

/// Kind and value count of every `pii` finding of the snapshot. Must run on the source
/// texts: both are parsed from the Russian title/description the core writes.
pub(crate) fn pii_meta(snap: &foca_core::api::Snapshot) -> BTreeMap<u64, (&'static str, u64)> {
    snap.findings
        .iter()
        .filter(|f| f.provenance.rule == "pii")
        .map(|f| (f.id, (pii_kind_of(f), pii_count(f))))
        .collect()
}

/// Number of values of a `pii` finding (from its description; markings count as one).
fn pii_count(f: &Finding) -> u64 {
    f.description
        .split_once("значений: ")
        .and_then(|(_, r)| {
            r.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        })
        .unwrap_or(1)
}

struct Groups<'a> {
    sigs: Vec<&'a Finding>,
    hidden: Vec<&'a Finding>,
    pii: Vec<&'a Finding>,
    links: Vec<&'a Finding>,
}

fn groups<'a>(c: &Ctx<'a>) -> Groups<'a> {
    let pick = |p: &dyn Fn(&str) -> bool| -> Vec<&'a Finding> {
        c.main
            .iter()
            .copied()
            .filter(|f| p(f.provenance.rule.as_str()))
            .collect()
    };
    Groups {
        sigs: pick(&|r| SIG_RULES.contains(&r)),
        hidden: pick(&|r| HIDDEN_RULES.contains(&r)),
        pii: pick(&|r| r == "pii"),
        links: pick(&|r| r == "doc.links"),
    }
}

fn doc_name(c: &Ctx, f: &Finding) -> String {
    f.doc
        .and_then(|d| c.doc_names.get(&d).cloned())
        .unwrap_or_else(|| "-".into())
}

fn rows(c: &Ctx, list: &[&Finding], html: bool) -> Vec<Vec<String>> {
    list.iter()
        .map(|f| {
            let title = crate::ftext::localize(f, c.o.lang).title;
            let enc = |s: &str| if html { c.h(s) } else { c.m(s) };
            vec![
                enc(&doc_name(c, f)),
                enc(&title),
                if html {
                    format!(
                        "<span class=\"badge {}\">{}</span>",
                        crate::data::sev_id(f.sev),
                        esc(c.sev(f.sev))
                    )
                } else {
                    mesc(c.sev(f.sev))
                },
            ]
        })
        .collect()
}

fn pii_rows(c: &Ctx, list: &[&Finding], html: bool) -> Vec<Vec<String>> {
    list.iter()
        .map(|f| {
            let enc = |s: &str| if html { c.h(s) } else { c.m(s) };
            let meta = c.pii.get(&f.id).copied().unwrap_or(("", 1));
            vec![
                enc(&doc_name(c, f)),
                enc(pii_kind(meta.0, c.o.lang)),
                meta.1.to_string(),
                if html {
                    esc(c.sev(f.sev))
                } else {
                    mesc(c.sev(f.sev))
                },
            ]
        })
        .collect()
}

fn html_table(h: &mut String, head: &[&str], rows: &[Vec<String>]) {
    crate::table::html_table(h, head, rows, &[]);
}

/// HTML subsection; nothing when no forensic finding is included.
pub fn html(c: &Ctx, h: &mut String) {
    let g = groups(c);
    if g.sigs.is_empty() && g.hidden.is_empty() && g.pii.is_empty() && g.links.is_empty() {
        return;
    }
    let t = strings(c.o.lang);
    let _ = write!(h, "<h3>{}</h3>", esc(t.title));
    for (title, list) in [
        (t.sigs, &g.sigs),
        (t.hidden, &g.hidden),
        (t.links, &g.links),
    ] {
        if !list.is_empty() {
            let _ = write!(h, "<h4>{}</h4>", esc(title));
            html_table(h, &[t.doc, t.finding, t.sev], &rows(c, list, true));
        }
    }
    if !g.pii.is_empty() {
        let _ = write!(
            h,
            "<h4>{}</h4><p class=\"small\">{}</p>",
            esc(t.pii),
            esc(t.pii_note)
        );
        html_table(
            h,
            &[t.doc, t.kind, t.count, t.sev],
            &pii_rows(c, &g.pii, true),
        );
    }
}

fn md_table(lang: Lang, o: &mut String, head: &[&str], rows: &[Vec<String>]) {
    crate::table::md_table(crate::i18n::strings(lang).no_data, o, head, rows);
}

/// Markdown subsection; nothing when no forensic finding is included.
pub fn md(c: &Ctx, o: &mut String) {
    let g = groups(c);
    if g.sigs.is_empty() && g.hidden.is_empty() && g.pii.is_empty() && g.links.is_empty() {
        return;
    }
    let t = strings(c.o.lang);
    let _ = writeln!(o, "### {}\n", mesc(t.title));
    for (title, list) in [
        (t.sigs, &g.sigs),
        (t.hidden, &g.hidden),
        (t.links, &g.links),
    ] {
        if !list.is_empty() {
            let _ = writeln!(o, "#### {}\n", mesc(title));
            md_table(
                c.o.lang,
                o,
                &[t.doc, t.finding, t.sev],
                &rows(c, list, false),
            );
        }
    }
    if !g.pii.is_empty() {
        let _ = writeln!(o, "#### {}\n\n*{}*\n", mesc(t.pii), mesc(t.pii_note));
        md_table(
            c.o.lang,
            o,
            &[t.doc, t.kind, t.count, t.sev],
            &pii_rows(c, &g.pii, false),
        );
    }
}
