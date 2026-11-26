//! Document hygiene: `hygiene_get` (grade A-F per document and for the set, with fix
//! steps) and `doc_clean` (clean copy + self-check "before/after" via `foca_meta::clean_and_verify`).
//!
//! Both work on a project (`{ project, ids? }`) or on a single file outside any project (`{ path }`,
//! e.g. a file received through the Android share sheet and copied into the private cache): the
//! file mode needs no project and makes no network requests.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use foca_meta::{CleanOptions, HygieneReport, Limits, VerifyReport};
use serde_json::{json, Value};

use crate::analysis::facts;
use crate::engine::{lock, Core};
use crate::util::arg_ids;
use crate::{CmdError, CmdResult};

/// Directory (under `<data>/clean/`) for clean copies of files outside a project.
const SHARED_DIR: &str = "shared";

fn bad_args(m: impl Into<String>) -> CmdError {
    CmdError::new("bad_args", m)
}

/// File name without any directory part, safe for the private directory.
pub(crate) fn safe_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let s: String = base
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let s = s.trim().trim_start_matches('.').to_string();
    let s: String = s.chars().take(120).collect();
    if s.is_empty() {
        "file".into()
    } else {
        s
    }
}

/// `report.pdf` → `report_clean.pdf`.
pub(crate) fn clean_name(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((b, e)) if !b.is_empty() => format!("{b}_clean.{e}"),
        _ => format!("{name}_clean"),
    }
}

fn ext_of(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, e)| e.to_lowercase())
        .unwrap_or_default()
}

/// Reads an input file of the file mode: must be a regular file within the parser size limit.
fn read_input(raw: &str) -> Result<(PathBuf, Vec<u8>), CmdError> {
    let p = Path::new(raw);
    let meta =
        std::fs::metadata(p).map_err(|_| CmdError::not_found(format!("файл не найден: {raw}")))?;
    if !meta.is_file() {
        return Err(bad_args("путь, не файл"));
    }
    if meta.len() > Limits::default().max_file {
        return Err(bad_args("файл больше 200 МБ"));
    }
    Ok((p.to_path_buf(), std::fs::read(p)?))
}

fn grade_json(r: &HygieneReport, extra: Value) -> Value {
    let mut v = serde_json::to_value(r).unwrap_or_else(|_| json!({}));
    if let (Some(o), Some(x)) = (v.as_object_mut(), extra.as_object()) {
        for (k, val) in x {
            o.insert(k.clone(), val.clone());
        }
    }
    v
}

fn set_json(reports: &[HygieneReport]) -> Value {
    serde_json::to_value(foca_meta::grade_set(reports)).unwrap_or_else(|_| json!({}))
}

fn grade_bytes(bytes: &[u8], name: &str) -> Result<HygieneReport, String> {
    let m = foca_meta::extract(bytes, Some(name), &Limits::default()).map_err(|e| e.to_string())?;
    Ok(foca_meta::grade_document(&m))
}

/// Result of cleaning one file.
struct Cleaned {
    /// Path of the clean copy (written only when cleaning succeeded).
    path: Option<PathBuf>,
    verify: Option<VerifyReport>,
    grade_before: Option<HygieneReport>,
    grade_after: Option<HygieneReport>,
    size_after: Option<u64>,
    /// Secrets found in the text of the clean copy (content, not metadata).
    secrets: Vec<String>,
    error: Option<String>,
}

fn clean_bytes(bytes: &[u8], name: &str, out: &Path, opts: &CleanOptions) -> Cleaned {
    let lim = Limits::default();
    let fmt = foca_meta::detect(bytes);
    let mut c = Cleaned {
        path: None,
        verify: None,
        grade_before: grade_bytes(bytes, name).ok(),
        grade_after: None,
        size_after: None,
        secrets: Vec::new(),
        error: None,
    };
    if !foca_meta::can_clean(fmt) {
        c.error = Some(format!(
            "формат {fmt:?}: очистка метаданных не поддерживается"
        ));
        return c;
    }
    match crate::util::catch_panic(|| {
        foca_meta::clean_and_verify(bytes, fmt, opts, &lim).map_err(|e| e.to_string())
    }) {
        Ok(r) => {
            if let Err(e) = std::fs::write(out, &r.bytes) {
                c.error = Some(format!("не удалось записать копию: {e}"));
                return c;
            }
            c.grade_after = grade_bytes(&r.bytes, name).ok();
            if let Ok(t) = foca_meta::text(&r.bytes, &lim) {
                c.secrets = foca_analysis::secrets::Rules::builtin()
                    .scan(&t, "текст")
                    .into_iter()
                    .map(|h| h.location)
                    .collect();
            }
            c.size_after = Some(r.bytes.len() as u64);
            c.path = Some(out.to_path_buf());
            c.verify = Some(r.report);
        }
        Err(e) => c.error = Some(e),
    }
    c
}

fn grade_letter(r: &Option<HygieneReport>) -> Value {
    r.as_ref()
        .and_then(|r| serde_json::to_value(r.grade).ok())
        .unwrap_or(Value::Null)
}

/// Sensitive fields the self-check saw removed or changed (top-level names: `author`, `xmp`, ...).
fn removed_fields(v: &VerifyReport) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for ch in &v.changes {
        let removed = !matches!(
            ch.change,
            foca_meta::ChangeKind::Kept | foca_meta::ChangeKind::Added
        );
        if ch.sensitive && removed {
            let top = ch
                .field
                .split(['.', '['])
                .next()
                .unwrap_or(&ch.field)
                .to_string();
            if !out.contains(&top) {
                out.push(top);
            }
        }
    }
    out
}

/// Common fields of a `doc_clean` record; `manual` gets the remaining sensitive fields too.
fn record(c: &Cleaned, mut manual: Vec<Value>) -> Value {
    if let Some(v) = &c.verify {
        if v.remaining > 0 {
            manual.push(json!({ "kind": "remaining", "where": format!("осталось полей метаданных: {}", v.remaining) }));
        }
        if !v.valid {
            manual.push(json!({ "kind": "invalid", "where": v.error.clone().unwrap_or_else(|| "копия не прошла самопроверку".into()) }));
        }
    }
    for s in &c.secrets {
        manual.push(json!({ "kind": "secret", "where": s }));
    }
    if let Some(e) = &c.error {
        manual.push(json!({ "kind": "format", "where": e }));
    }
    let clean = manual.is_empty();
    json!({
        "path": c.path.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "manual": manual,
        "clean": clean,
        "verify": c.verify,
        "grade_before": grade_letter(&c.grade_before),
        "grade_after": grade_letter(&c.grade_after),
        "size": c.size_after,
    })
}

fn merge(mut a: Value, b: Value) -> Value {
    if let (Some(o), Value::Object(x)) = (a.as_object_mut(), b) {
        o.extend(x);
    }
    a
}

/// `hygiene_get { project, ids? } | { path, name? }` → `{ set, docs: [{ id, name, ext, grade,
/// score, format, cleanable, issues }] }`.
pub(crate) async fn hygiene_get(core: &Core, a: &Value) -> CmdResult {
    if let Some(raw) = a.get("path").and_then(Value::as_str) {
        let (path, bytes) = read_input(raw)?;
        let name = safe_name(
            a.get("name")
                .and_then(Value::as_str)
                .unwrap_or(&path.to_string_lossy()),
        );
        let n2 = name.clone();
        let r = tokio::task::spawn_blocking(move || {
            crate::util::catch_panic(|| grade_bytes(&bytes, &n2))
        })
        .await
        .map_err(CmdError::internal)?
        .map_err(|e| bad_args(format!("файл не разобран: {e}")))?;
        let doc = grade_json(
            &r,
            json!({ "id": Value::Null, "name": name, "ext": ext_of(&name) }),
        );
        return Ok(json!({ "set": set_json(std::slice::from_ref(&r)), "docs": [doc] }));
    }
    let id = core.project_arg(a)?;
    let only = arg_ids(a, "ids");
    let db = core.db(&id)?;
    let docs = lock(&db).documents(false)?;
    let mut reports = Vec::new();
    let mut out = Vec::new();
    for d in docs {
        if !only.is_empty() && !only.contains(&d.doc.id) {
            continue;
        }
        let Some(m) = &d.doc.metadata else { continue };
        let r = foca_meta::grade_document(m);
        out.push(grade_json(
            &r,
            json!({ "id": d.doc.id, "name": d.doc.name, "ext": d.doc.ext }),
        ));
        reports.push(r);
    }
    Ok(json!({ "set": set_json(&reports), "docs": out }))
}

/// `doc_clean { project, ids, options? } | { path, name?, options? }` → `{ cleaned: [...] }`.
pub(crate) async fn doc_clean(core: &Core, a: &Value) -> CmdResult {
    let opts: CleanOptions = match a.get("options") {
        Some(o) if !o.is_null() => {
            serde_json::from_value(o.clone()).map_err(|e| bad_args(format!("options: {e}")))?
        }
        _ => CleanOptions::default(),
    };
    let at = core.now_iso();
    if let Some(raw) = a.get("path").and_then(Value::as_str) {
        let (path, bytes) = read_input(raw)?;
        let name = safe_name(
            a.get("name")
                .and_then(Value::as_str)
                .unwrap_or(&path.to_string_lossy()),
        );
        let out_dir = core.cfg.data_dir.join("clean").join(SHARED_DIR);
        std::fs::create_dir_all(&out_dir)?;
        let cname = clean_name(&name);
        let out = out_dir.join(&cname);
        let n2 = name.clone();
        let c = tokio::task::spawn_blocking(move || clean_bytes(&bytes, &n2, &out, &opts))
            .await
            .map_err(CmdError::internal)?;
        let removed = c.verify.as_ref().map(removed_fields).unwrap_or_default();
        let r = merge(
            json!({ "id": Value::Null, "name": cname, "source": name, "removed": removed, "at": at }),
            record(&c, Vec::new()),
        );
        return Ok(json!({ "cleaned": [r] }));
    }
    let id = core.project_arg(a)?;
    let ids = arg_ids(a, "ids");
    let db = core.db(&id)?;
    let out_dir = core.cfg.data_dir.join("clean").join(&id);
    std::fs::create_dir_all(&out_dir)?;
    let mut res = Vec::new();
    for did in ids {
        let (stored, ui, secrets) = {
            let d = lock(&db);
            let s = d
                .document(did)
                .map_err(|_| CmdError::not_found(format!("Документ {did} не найден")))?;
            let ui = d.ui_docs()?.into_iter().find(|x| x.id == did);
            let secrets = d.entity("secrets")?;
            (s, ui, secrets)
        };
        let mut removed: Vec<String> = Vec::new();
        if let Some(u) = &ui {
            let flags = [
                (u.author.is_some() || u.last_modified_by.is_some(), "author"),
                (u.company.is_some(), "company"),
                (u.folder.is_some(), "path"),
                (u.printer.is_some(), "printer"),
                (u.gps.is_some(), "gps"),
                (u.camera.is_some(), "camera"),
                (!u.revisions.is_empty(), "revisions"),
                (u.software.is_some(), "software"),
                (u.thumb_diff, "thumbnail"),
            ];
            removed.extend(flags.iter().filter(|f| f.0).map(|f| f.1.to_string()));
        }
        // Secrets the analysis found in this document: the cleaner keeps the text.
        let manual: Vec<Value> = secrets
            .as_array()
            .map(|l| {
                l.iter()
                    .filter(|s| s["doc"].as_u64() == Some(did))
                    .map(|s| json!({ "kind": "secret", "where": s["where"] }))
                    .collect()
            })
            .unwrap_or_default();
        let name = clean_name(&safe_name(&stored.doc.name));
        let bytes = stored
            .local_path
            .as_deref()
            .and_then(|p| std::fs::read(p).ok());
        let rec = match bytes {
            Some(b) => {
                let out = out_dir.join(&name);
                let src = stored.doc.name.clone();
                let opts = opts.clone();
                let mut c = tokio::task::spawn_blocking(move || clean_bytes(&b, &src, &out, &opts))
                    .await
                    .map_err(CmdError::internal)?;
                if !manual.is_empty() {
                    c.secrets.clear(); // already listed from the analysis
                }
                record(&c, manual)
            }
            None => {
                let mut m = manual;
                m.push(json!({ "kind": "format", "where": "файл документа не скачан" }));
                json!({ "path": Value::Null, "clean": false, "manual": m, "verify": Value::Null,
                    "grade_before": Value::Null, "grade_after": Value::Null, "size": Value::Null })
            }
        };
        // `path` is the cleaned copy in the private directory (`<data>/clean/<project>/<name>`) for sharing
        res.push(merge(
            json!({ "id": did, "name": name, "removed": removed, "at": at }),
            rec,
        ));
    }
    let d = lock(&db);
    let mut cl: BTreeMap<String, Value> = facts::get(&d, facts::K_CLEANED);
    for r in &res {
        cl.insert(
            r["id"].to_string(),
            json!({ "at": r["at"], "name": r["name"], "manual": r["manual"].as_array().map_or(0, |m| m.len()) }),
        );
    }
    facts::put(&d, facts::K_CLEANED, &cl)?;
    Ok(json!({ "cleaned": res }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_flat_and_safe() {
        assert_eq!(safe_name("/sdcard/Download/Отчёт.pdf"), "Отчёт.pdf");
        assert_eq!(safe_name("..\\..\\a:b.docx"), "a_b.docx");
        assert_eq!(safe_name("..."), "file");
        assert_eq!(clean_name("a.b.pdf"), "a.b_clean.pdf");
        assert_eq!(clean_name("README"), "README_clean");
        assert_eq!(clean_name(".hidden"), ".hidden_clean");
    }
}
