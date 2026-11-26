//! Report language guard: a project with at least one finding of every rule the analysis can
//! produce, rendered in Ukrainian and English, must not contain Russian outside data fields.
//!
//! Real findings come from scans on the local stand (documents, insights, recon, web audit,
//! network); every rule the stand does not produce gets a synthetic finding built from the
//! rule's Russian catalog templates (`locales/ru/findings.json`) filled with sample values.
//! Data (hosts, file names, people, evidence, URLs) is removed before the check.

use std::collections::BTreeSet;

use crate::common;
use foca_core::api::{Finding, Snapshot};
use foca_report::{build_report_with_log, Lang, ReportFormat, ReportOptions, Sections, Template};
use serde_json::{json, Value};

/// Letters Ukrainian and English never use.
const RU_LETTERS: &[char] = &['ы', 'э', 'ъ', 'ё', 'Ы', 'Э', 'Ъ', 'Ё'];

/// Common Russian words spelled with letters Ukrainian shares (whole words, lowercase).
const RU_WORDS: &[&str] = &[
    "если",
    "это",
    "или",
    "что",
    "как",
    "нет",
    "ещё",
    "еще",
    "его",
    "она",
    "они",
    "который",
    "также",
    "только",
    "найден",
    "найдено",
    "найдена",
    "сверьте",
    "версия",
    "хосты",
    "затронутые",
    "сопоставил",
    "проверки",
    "снята",
    "поддержки",
    "исправления",
    "обнаружен",
    "обнаружено",
    "уязвимости",
    "уязвимое",
    "вне",
    "скоупа",
    "находка",
    "риска",
    "данные",
    "сайта",
    "файлов",
    "документов",
    "запросов",
    "ошибка",
    "перебор",
    "разведка",
];

fn ru_hits(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let low = l.to_lowercase();
        let words: Vec<&str> = low
            .split(|c: char| !c.is_alphabetic())
            .filter(|w| !w.is_empty())
            .collect();
        let bad_word = words.iter().find(|w| RU_WORDS.contains(w));
        if l.contains(RU_LETTERS) || bad_word.is_some() {
            let cut: String = l.chars().take(220).collect();
            out.push(match bad_word {
                Some(w) => format!("[{w}] {cut}"),
                None => cut,
            });
        }
    }
    out
}

/// Every string of the snapshot except the finding texts that must be translated.
fn data_strings(snap: &Snapshot) -> Vec<String> {
    fn walk(v: &Value, skip: &[&str], out: &mut BTreeSet<String>) {
        match v {
            Value::String(s) => {
                for part in s.split('\n') {
                    let p = part.trim();
                    if p.chars().count() >= 4 {
                        out.insert(p.to_string());
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, skip, out)),
            Value::Object(m) => {
                for (k, x) in m {
                    if !skip.contains(&k.as_str()) {
                        walk(x, skip, out);
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    let mut v = serde_json::to_value(snap).unwrap();
    let findings = v
        .get_mut("findings")
        .map(Value::take)
        .unwrap_or(Value::Null);
    walk(&v, &[], &mut out);
    for f in findings.as_array().into_iter().flatten() {
        // Evidence, hosts, URLs and notes are data; titles, descriptions and recommendations
        // are core texts the report translates.
        walk(
            f,
            &[
                "title",
                "description",
                "recommendation",
                "source",
                "category",
                "provenance",
                "tags",
            ],
            &mut out,
        );
        for x in f["provenance"]["docs"].as_array().into_iter().flatten() {
            walk(x, &[], &mut out);
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    // Longest first so a long value is removed before a shorter one inside it.
    v.sort_by_key(|s| std::cmp::Reverse(s.len()));
    v
}

/// Removes a tag with its content (`<pre>…</pre>`).
fn drop_blocks(s: &str, tag: &str) -> String {
    let (open, close) = (format!("<{tag}"), format!("</{tag}>"));
    let mut out = String::with_capacity(s.len());
    let mut r = s;
    while let Some(i) = r.find(&open) {
        out.push_str(&r[..i]);
        r = r[i..]
            .find(&close)
            .map_or("", |j| &r[i + j + close.len()..]);
    }
    out.push_str(r);
    out
}

fn strip_html(s: &str) -> String {
    // Scripts, styles, diagrams and <pre>/<code> evidence blocks are not report prose.
    let mut s = s.to_string();
    for tag in ["script", "style", "svg", "pre", "code"] {
        s = drop_blocks(&s, tag);
    }
    let mut text = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                text.push('\n');
            }
            _ if !in_tag => text.push(c),
            _ => {}
        }
    }
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

fn strip_md(s: &str) -> String {
    let mut out = String::new();
    let mut fence = false;
    for line in s.lines() {
        if line.trim_start().starts_with("```") {
            fence = !fence;
            continue;
        }
        if fence {
            continue;
        }
        // Inline code spans hold evidence and identifiers.
        let mut l = String::new();
        let mut code = false;
        for c in line.chars() {
            if c == '`' {
                code = !code;
                continue;
            }
            if !code {
                l.push(c);
            }
        }
        out.push_str(&l.replace('\\', ""));
        out.push('\n');
    }
    out
}

/// Blanks data values in the text; only whole-word occurrences, so a short value never cuts
/// a translated word in half.
fn without_data(text: &str, data: &[String]) -> String {
    let mut t = text.to_string();
    for d in data {
        if !t.contains(d.as_str()) {
            continue;
        }
        let mut out = String::with_capacity(t.len());
        let mut rest = t.as_str();
        while let Some(i) = rest.find(d.as_str()) {
            let before = rest[..i].chars().next_back();
            let after = rest[i + d.len()..].chars().next();
            let edge = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric());
            out.push_str(&rest[..i]);
            if edge(before) && edge(after) {
                out.push(' ');
            } else {
                out.push_str(d);
            }
            rest = &rest[i + d.len()..];
        }
        out.push_str(rest);
        t = out;
    }
    t
}

#[derive(serde::Deserialize)]
struct CatalogEntry {
    rules: String,
    pattern: String,
}

fn ru_catalog() -> Vec<CatalogEntry> {
    #[derive(serde::Deserialize)]
    struct F {
        catalog: Vec<CatalogEntry>,
    }
    let p = root().join("../../locales/ru/findings.json");
    let f: F = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    f.catalog
}

fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rule_matches(spec: &str, rule: &str) -> bool {
    spec.split(',').any(|s| {
        let s = s.trim();
        s == rule || s.strip_suffix('*').is_some_and(|p| rule.starts_with(p))
    })
}

/// Rule ids the analysis can produce: the standards mapping, the translation catalog and the
/// infrastructure rule table. A family spec (`mail-*`) stands for one sample member.
fn rule_ids(cat: &[CatalogEntry]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let toml_src =
        std::fs::read_to_string(root().join("../foca-analysis/signatures/standards.toml")).unwrap();
    let t: toml::Value = toml::from_str(&toml_src).unwrap();
    for r in t["rule"].as_array().unwrap() {
        out.insert(r["id"].as_str().unwrap().to_string());
    }
    for e in cat {
        for s in e.rules.split(',').map(str::trim) {
            match s.strip_suffix('*') {
                Some("") => {}
                Some(p) => {
                    out.insert(format!("{p}sample"));
                }
                None => {
                    out.insert(s.to_string());
                }
            }
        }
    }
    for r in foca_analysis::infra::RULES {
        out.insert(foca_analysis::infra::rule_id(r.code));
    }
    out
}

/// Fills a Russian template with sample values (`{}` → data token, `{n}` → number).
fn sample(pattern: &str, k: &mut usize) -> String {
    let mut out = String::new();
    let mut rest = pattern;
    while !rest.is_empty() {
        let next = ["{}", "{n}", "{w}"]
            .iter()
            .filter_map(|p| rest.find(p).map(|i| (i, *p)))
            .min_by_key(|(i, _)| *i);
        let Some((i, p)) = next else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..i]);
        *k += 1;
        out.push_str(match p {
            "{}" => "Z9data",
            "{n}" => ["2", "5", "11", "21"][*k % 4],
            // `{w}` follows a number: the plural form of that number.
            _ => "документов",
        });
        rest = &rest[i + p.len()..];
    }
    out
}

fn synthetic(rule: &str, cat: &[CatalogEntry], base: &Finding, id: u64) -> Option<Finding> {
    let mut k = 0;
    let texts: Vec<String> = cat
        .iter()
        .filter(|e| rule_matches(&e.rules, rule))
        .map(|e| sample(&e.pattern, &mut k))
        .collect();
    let (title, rest) = texts.split_first()?;
    let mut f = base.clone();
    f.id = id;
    f.provenance.rule = rule.into();
    f.provenance.docs.clear();
    f.title = title.clone();
    f.description = rest.join("\n");
    f.recommendation = String::new();
    f.evidence = String::new();
    f.tags.clear();
    f.status = foca_core::FindingStatus::New;
    Some(f)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uk_and_en_reports_have_no_russian_for_any_rule() {
    let e = common::env(0).await;
    let id = e.project("example.test").await;
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive",
            "sources": ["crt", "wayback", "cc", "recon", "webaudit"] }),
    )
    .await;
    e.wait().await;
    // Network, mail and infrastructure findings of the standard profile.
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "std", "sources": ["crt"] }),
    )
    .await;
    e.wait().await;
    let st = foca_store::Store::open(e.dir.path()).unwrap();
    let mut snap: Snapshot = st.project_snapshot(&id).unwrap();
    assert!(!snap.findings.is_empty());

    let cat = ru_catalog();
    let have: BTreeSet<String> = snap
        .findings
        .iter()
        .map(|f| f.provenance.rule.clone())
        .collect();
    eprintln!("rules from the stand: {have:?}");
    let base = snap.findings[0].clone();
    let mut missing_catalog = Vec::new();
    for (i, rule) in rule_ids(&cat).iter().enumerate() {
        if have.contains(rule) {
            continue;
        }
        match synthetic(rule, &cat, &base, 900_000 + i as u64) {
            Some(f) => snap.findings.push(f),
            None => missing_catalog.push(rule.clone()),
        }
    }
    assert!(
        missing_catalog.is_empty(),
        "rules without any catalog template (texts stay Russian): {missing_catalog:?}"
    );
    let data = data_strings(&snap);

    let mut bad: BTreeSet<String> = BTreeSet::new();
    for lang in [Lang::Uk, Lang::En] {
        for tpl in [
            Template::Full,
            Template::Executive,
            Template::Compliance,
            Template::Lab,
        ] {
            for fmt in [ReportFormat::Md, ReportFormat::Html] {
                let o = ReportOptions {
                    tpl,
                    fmt,
                    lang,
                    sections: if tpl == Template::Full {
                        Sections::all()
                    } else {
                        Sections::for_template(tpl)
                    },
                    company: "Example Audit".into(),
                    ..Default::default()
                };
                let a = build_report_with_log(
                    &snap,
                    &[],
                    &o,
                    time::macros::datetime!(2026-11-20 12:00 UTC),
                );
                let raw = String::from_utf8(a.bytes).unwrap();
                let text = match fmt {
                    ReportFormat::Html => strip_html(&raw),
                    _ => strip_md(&raw),
                };
                for h in ru_hits(&without_data(&text, &data)) {
                    bad.insert(format!("{lang:?}/{tpl:?}/{fmt:?}: {h}"));
                }
            }
        }
    }
    let list: Vec<&String> = bad.iter().take(120).collect();
    assert!(
        bad.is_empty(),
        "{} lines with Russian in UK/EN reports:\n{}",
        bad.len(),
        list.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}
