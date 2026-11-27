//! Developer artefacts in JSON: JavaScript source maps (`.map`) and Jupyter notebooks
//! (`.ipynb`). Source maps list original source files, often with absolute build paths that
//! name the developer; notebooks keep kernel/language versions and cell outputs with local
//! paths, user names and e-mail addresses in tracebacks.

use foca_core::{DocFormat, Metadata, PersonRole};
use serde_json::Value;

use crate::util::{clean_str, truncate};
use crate::MetaError;

const MAX_SOURCES: usize = 5000;
const MAX_TEXT: usize = 4 << 20;

/// Strips the `)]}'` anti-XSSI prefix some servers put before source maps.
fn json_body(b: &[u8]) -> &[u8] {
    let b = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
    if b.starts_with(b")]}'") {
        let nl = b.iter().position(|&c| c == b'\n').unwrap_or(b.len());
        &b[nl.min(b.len())..]
    } else {
        b
    }
}

pub(crate) fn looks_like_sourcemap(head: &str) -> bool {
    let t = head.trim_start_matches(")]}'").trim_start();
    t.starts_with('{') && t.contains("\"mappings\"") && t.contains("\"sources\"")
}

pub(crate) fn looks_like_notebook(head: &str) -> bool {
    let t = head.trim_start();
    t.starts_with('{') && t.contains("\"cells\"") && t.contains("\"nbformat")
        || (t.starts_with('{') && t.contains("\"nbformat\"") && t.contains("\"metadata\""))
}

fn parse(b: &[u8], what: &'static str) -> Result<Value, MetaError> {
    serde_json::from_slice(json_body(b)).map_err(|e| MetaError::malformed(what, e))
}

pub fn extract_sourcemap(b: &[u8]) -> Result<Metadata, MetaError> {
    let v = parse(b, "source map")?;
    let mut meta = Metadata::new(DocFormat::SourceMap);
    if let Some(f) = v.get("file").and_then(Value::as_str).and_then(clean_str) {
        meta.title = Some(truncate(&f, 512));
    }
    let root = v
        .get("sourceRoot")
        .and_then(Value::as_str)
        .and_then(clean_str);
    if let Some(r) = &root {
        meta.fields
            .insert("sourcemap:sourceRoot".into(), truncate(r, 1024));
        add_source_path(&mut meta, r);
    }
    let sources: Vec<String> = v
        .get("sources")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .take(MAX_SOURCES)
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let mut packages: Vec<String> = Vec::new();
    for s in &sources {
        add_source_path(&mut meta, s);
        if let Some(p) = npm_package(s) {
            if !packages.contains(&p) && packages.len() < 200 {
                packages.push(p);
            }
        }
        if let Some(rest) = s.strip_prefix("webpack://") {
            let ns = rest.trim_start_matches('/').split('/').next().unwrap_or("");
            if !ns.is_empty() && ns != "." && !ns.starts_with('(') {
                meta.fields
                    .entry("sourcemap:webpack_namespace".into())
                    .or_insert_with(|| truncate(ns, 128));
            }
            Metadata::add_unique(&mut meta.software, "webpack");
        } else if s.contains("/@vite/") || s.starts_with("vite/") {
            Metadata::add_unique(&mut meta.software, "Vite");
        }
    }
    meta.stats.insert("sources".into(), sources.len() as u64);
    if !packages.is_empty() {
        meta.stats
            .insert("npm_packages".into(), packages.len() as u64);
        meta.fields
            .insert("sourcemap:packages".into(), packages.join(", "));
    }
    let content = v
        .get("sourcesContent")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter(|x| x.is_string()).count())
        .unwrap_or(0);
    if content > 0 {
        meta.stats.insert("sources_content".into(), content as u64);
        meta.fields.insert(
            "sourcemap:sourcesContent".into(),
            format!("{content} embedded source files"),
        );
    }
    Ok(meta)
}

/// Source text embedded in the map, for secret scanning.
pub fn sourcemap_text(b: &[u8]) -> Result<String, MetaError> {
    let v = parse(b, "source map")?;
    let mut out = String::new();
    for s in v
        .get("sourcesContent")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(s) = s.as_str() {
            if out.len() + s.len() > MAX_TEXT {
                break;
            }
            out.push_str(s);
            out.push('\n');
        }
    }
    Ok(out)
}

/// Adds the absolute path behind a source entry (`file:///home/u/x`, `webpack:///C:/Users/..`).
fn add_source_path(meta: &mut Metadata, s: &str) {
    let mut p = s;
    for pre in ["webpack://", "file://"] {
        if let Some(r) = p.strip_prefix(pre) {
            p = r;
        }
    }
    let p = p.trim_start_matches('/');
    let cand = if p.len() > 2 && p.as_bytes()[1] == b':' {
        p.replace('/', "\\")
    } else {
        format!("/{p}")
    };
    let raw = if s.starts_with('/') || s.starts_with("\\\\") || s.get(1..2) == Some(":") {
        s.to_string()
    } else {
        cand
    };
    let lower = raw.to_ascii_lowercase();
    if lower.contains("/users/")
        || lower.contains("\\users\\")
        || lower.starts_with("/home/")
        || lower.starts_with("\\\\")
        || lower.contains("/builds/")
        || lower.starts_with("/var/")
        || lower.starts_with("/opt/")
        || lower.starts_with("/srv/")
    {
        crate::paths::add_path(meta, &raw, "sourcemap:sources");
    }
}

/// `webpack:///./node_modules/@scope/pkg/x.js` -> `@scope/pkg`.
fn npm_package(s: &str) -> Option<String> {
    let i = s.rfind("node_modules/")? + "node_modules/".len();
    let rest = &s[i..];
    let mut parts = rest.split('/');
    let first = parts.next()?;
    let name = if first.starts_with('@') {
        format!("{first}/{}", parts.next()?)
    } else {
        first.to_string()
    };
    (!name.is_empty() && name.len() < 128).then_some(name)
}

pub fn extract_notebook(b: &[u8]) -> Result<Metadata, MetaError> {
    let v = parse(b, "ipynb")?;
    let mut meta = Metadata::new(DocFormat::Ipynb);
    let md = v.get("metadata").cloned().unwrap_or(Value::Null);
    let s = |p: &[&str]| -> Option<String> {
        let mut cur = &md;
        for k in p {
            cur = cur.get(*k)?;
        }
        cur.as_str().and_then(clean_str).map(|x| truncate(&x, 256))
    };
    if let Some(k) = s(&["kernelspec", "display_name"]) {
        meta.fields.insert("ipynb:kernel".into(), k.clone());
        meta.application = Some(k);
    }
    if let Some(k) = s(&["kernelspec", "name"]) {
        meta.fields.insert("ipynb:kernel_name".into(), k);
    }
    if let (Some(l), ver) = (
        s(&["language_info", "name"]),
        s(&["language_info", "version"]),
    ) {
        let sw = match &ver {
            Some(v) => format!("{l} {v}"),
            None => l.clone(),
        };
        Metadata::add_unique(&mut meta.software, &sw);
        meta.fields.insert("ipynb:language".into(), sw);
    }
    if md.get("colab").is_some() {
        Metadata::add_unique(&mut meta.software, "Google Colab");
    }
    if let Some(t) = s(&["title"]) {
        meta.title = Some(t);
    }
    if let Some(a) = md.get("authors").and_then(Value::as_array) {
        for a in a.iter().take(20) {
            if let Some(n) = a.get("name").and_then(Value::as_str) {
                meta.add_person(n, PersonRole::Author, "ipynb:metadata.authors");
            }
        }
    }
    if let (Some(maj), Some(min)) = (
        v.get("nbformat").and_then(Value::as_u64),
        v.get("nbformat_minor").and_then(Value::as_u64),
    ) {
        meta.fields
            .insert("ipynb:nbformat".into(), format!("{maj}.{min}"));
    }
    let cells = v
        .get("cells")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    meta.stats.insert("cells".into(), cells.len() as u64);
    let mut times: Vec<String> = Vec::new();
    let mut outputs = 0u64;
    let mut budget = MAX_TEXT;
    for c in cells.iter().take(10_000) {
        if let Some(t) = c
            .pointer("/metadata/execution/iopub.execute_input")
            .and_then(Value::as_str)
        {
            if times.len() < 10_000 {
                times.push(truncate(t, 64));
            }
        }
        let src = join_text(c.get("source"));
        scan_text(&mut meta, &src, "ipynb:source", &mut budget);
        for o in c
            .get("outputs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(200)
        {
            outputs += 1;
            let mut t = join_text(o.get("text"));
            t.push_str(&join_text(o.get("traceback")));
            t.push_str(&join_text(o.pointer("/data/text~1plain")));
            scan_text(&mut meta, &strip_ansi(&t), "ipynb:output", &mut budget);
        }
    }
    meta.stats.insert("outputs".into(), outputs);
    times.sort();
    meta.created = times.first().cloned();
    meta.modified = times.last().cloned();
    Ok(meta)
}

/// Cell sources and outputs, for secret scanning.
pub fn notebook_text(b: &[u8]) -> Result<String, MetaError> {
    let v = parse(b, "ipynb")?;
    let mut out = String::new();
    for c in v
        .get("cells")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let t = join_text(c.get("source"));
        if out.len() + t.len() > MAX_TEXT {
            break;
        }
        out.push_str(&t);
        out.push('\n');
    }
    Ok(out)
}

fn join_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => {
            let mut out = String::new();
            for x in a.iter().take(10_000) {
                if let Some(s) = x.as_str() {
                    out.push_str(s);
                    if !s.ends_with('\n') {
                        out.push('\n');
                    }
                }
            }
            out
        }
        _ => String::new(),
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            if it.peek() == Some(&'[') {
                it.next();
                for d in it.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn scan_text(meta: &mut Metadata, t: &str, source: &str, budget: &mut usize) {
    if t.is_empty() || *budget == 0 {
        return;
    }
    let t = &t[..crate::util::floor_char_boundary(t, t.len().min(*budget))];
    *budget -= t.len();
    for p in crate::paths::find_paths(t).into_iter().take(200) {
        crate::paths::add_path(meta, &p, source);
    }
    for e in crate::paths::find_emails(t).into_iter().take(100) {
        Metadata::add_unique(&mut meta.emails, &e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_names() {
        assert_eq!(
            npm_package("webpack:///./node_modules/@scope/pkg/x.js").as_deref(),
            Some("@scope/pkg")
        );
        assert_eq!(
            npm_package("webpack:///node_modules/lodash/lodash.js").as_deref(),
            Some("lodash")
        );
        assert_eq!(npm_package("src/app.js"), None);
    }

    #[test]
    fn ansi() {
        assert_eq!(strip_ansi("\u{1b}[0;31mError\u{1b}[0m x"), "Error x");
    }
}
