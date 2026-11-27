//! Commands for offline import of files, folders and ZIP archives (no network at all),
//! full-text search over document text, user search rules and per-document forensic details.
//!
//! Offline import safety: archive member names are labels only and never become file-system
//! paths (documents are stored under their SHA-256), every file is parsed under the `Limits`
//! budget in a blocking task with a wall-clock timeout, and the whole import has file count and
//! total size limits.

use std::path::{Path, PathBuf};
use std::time::Duration;

use foca_analysis::rules::{self, RuleSet, RulesConfig, UserRule};
use foca_core::{DocFormat, DocStatus, Severity};
use foca_store::{AddDoc, SearchOpts};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::engine::{lock, Core};
use crate::util::{self, arg_str};
use crate::{CmdError, CmdResult};

/// Default and hard maximum of files per import.
const MAX_FILES: usize = 500;
const MAX_FILES_HARD: usize = 2000;
/// Default and hard maximum of total bytes per import (archive members included).
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_BYTES_HARD: u64 = 2 * 1024 * 1024 * 1024;
/// Largest single file (or archive member).
const MAX_FILE: u64 = 100 * 1024 * 1024;
/// Wall-clock budget for parsing one file.
const FILE_TIMEOUT: Duration = Duration::from_secs(30);
/// Nesting of archives expanded into separate documents.
const MAX_ZIP_DEPTH: u32 = 2;

/// One file to import: label (never a path) and bytes.
struct Item {
    name: String,
    source: String,
    bytes: Vec<u8>,
    /// An archive already expanded into separate documents: parse without embedded children.
    container: bool,
}

#[derive(Default)]
struct Budget {
    files: usize,
    bytes: u64,
    max_files: usize,
    max_bytes: u64,
    skipped: Vec<Value>,
}

impl Budget {
    fn take(&mut self, name: &str, size: u64) -> bool {
        if self.files >= self.max_files {
            self.skip(name, "too_many_files");
            return false;
        }
        if size > MAX_FILE {
            self.skip(name, "file_too_large");
            return false;
        }
        if self.bytes + size > self.max_bytes {
            self.skip(name, "total_too_large");
            return false;
        }
        self.files += 1;
        self.bytes += size;
        true
    }

    fn skip(&mut self, name: &str, reason: &str) {
        if self.skipped.len() < 200 {
            self.skipped.push(json!({ "name": name, "reason": reason }));
        }
    }
}

/// A display label from an archive member name or a picked file name: the last path component,
/// control and markup characters removed, at most 120 characters. Never used as a path.
/// Deepest folder level walked when a folder is given as an input path.
const MAX_DIR_DEPTH: usize = 16;

/// Expands input paths into a sorted list of files: folders are walked recursively (symbolic
/// links inside them are not followed, so link cycles cannot loop), plain paths are kept as is
/// and checked by the caller. The walk stops once the file budget is exceeded.
fn input_files(paths: &[&str], budget: &mut Budget) -> Vec<PathBuf> {
    fn walk(dir: &Path, depth: usize, cap: usize, out: &mut Vec<PathBuf>, budget: &mut Budget) {
        if depth > MAX_DIR_DEPTH {
            budget.skip(&label(&dir.to_string_lossy()), "too_deep");
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            budget.skip(&label(&dir.to_string_lossy()), "unreadable");
            return;
        };
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if out.len() > cap {
                return;
            }
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                walk(&e.path(), depth + 1, cap, out, budget);
            } else if ft.is_file() {
                out.push(e.path());
            }
        }
    }
    let cap = budget.max_files;
    let mut out = Vec::new();
    for p in paths {
        let path = Path::new(p);
        if std::fs::metadata(path).is_ok_and(|m| m.is_dir()) {
            walk(path, 0, cap, &mut out, budget);
        } else {
            out.push(path.to_path_buf());
        }
    }
    out
}

pub(crate) fn label(raw: &str) -> String {
    let last = raw
        .rsplit(['/', '\\'])
        .find(|s| !s.is_empty() && *s != "." && *s != "..")
        .unwrap_or("file");
    let clean: String = last
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | '"' | '`'))
        .take(120)
        .collect();
    if clean.trim().is_empty() {
        "file".into()
    } else {
        clean
    }
}

/// Safe storage extension: `[a-z0-9]{1,8}` from the label, otherwise `bin`.
fn safe_ext(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((_, e))
            if !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            e.to_ascii_lowercase()
        }
        _ => "bin".into(),
    }
}

fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04") && foca_meta::detect(bytes) == DocFormat::Zip
}

/// Expands `item` into `out`: archives become their members (recursively up to
/// [`MAX_ZIP_DEPTH`]) plus the archive itself as a container document.
fn expand(item: Item, depth: u32, budget: &mut Budget, out: &mut Vec<Item>, warn: &mut Vec<Value>) {
    if depth < MAX_ZIP_DEPTH && is_zip(&item.bytes) {
        let lim = foca_meta::Limits {
            max_file: MAX_FILE.min(budget.max_bytes.saturating_sub(budget.bytes)),
            max_unzipped_total: budget.max_bytes.saturating_sub(budget.bytes),
            max_entries: 5000,
            ..foca_meta::Limits::default()
        };
        let mut members: Vec<Item> = Vec::new();
        let src = format!("zip:{}", item.name);
        let r = foca_meta::for_each_zip_member(&item.bytes, &lim, |name, b| {
            members.push(Item {
                name: label(name),
                source: src.clone(),
                bytes: b.to_vec(),
                container: false,
            });
        });
        if let Err(e) = r {
            warn.push(json!({ "name": item.name, "error": e.to_string() }));
        }
        let name = item.name.clone();
        if budget.take(&name, item.bytes.len() as u64) {
            out.push(Item {
                container: true,
                ..item
            });
        }
        for m in members {
            expand(m, depth + 1, budget, out, warn);
        }
        return;
    }
    if budget.take(&item.name, item.bytes.len() as u64) {
        out.push(item);
    }
}

fn parse_one(
    bytes: &[u8],
    name: &str,
    container: bool,
) -> Result<(foca_core::Metadata, Option<String>), String> {
    util::catch_panic(|| {
        let mut lim = foca_meta::Limits::default();
        if container {
            // Members are separate documents; parsing them again as children would duplicate
            // every finding.
            lim.max_depth = 0;
        }
        let m = foca_meta::extract(bytes, Some(name), &lim).map_err(|e| e.to_string())?;
        let t = foca_meta::text(bytes, &lim).ok();
        Ok((m, t))
    })
}

/// `import_offline { project?, name?, domain?, paths?: [string], files?: [{ name, data }],
/// max_files?, max_mb? }`: creates (or reuses) a project and parses local files, folders
/// already copied by the platform picker and ZIP archives without a single network request.
pub(crate) async fn import_offline(core: &Core, a: &Value) -> CmdResult {
    let project = match a.get("project").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => {
            let name = arg_str(a, "name")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .unwrap_or_else(|| {
                    let now = core.clock.now();
                    format!(
                        "Офлайн-разбор {:04}-{:02}-{:02}",
                        now.year(),
                        u8::from(now.month()),
                        now.day()
                    )
                });
            let targets: Vec<Value> = arg_str(a, "domain")
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(|d| vec![json!(d)])
                .unwrap_or_default();
            let s = crate::cmds::projects::project_create(
                core,
                &json!({ "name": name, "targets": targets }),
            )?;
            s["id"]
                .as_str()
                .ok_or_else(|| CmdError::internal("project id"))?
                .to_string()
        }
    };
    let db = core.db(&project)?;
    let mut budget = Budget {
        max_files: a
            .get("max_files")
            .and_then(Value::as_u64)
            .map(|n| (n as usize).clamp(1, MAX_FILES_HARD))
            .unwrap_or(MAX_FILES),
        max_bytes: a
            .get("max_mb")
            .and_then(Value::as_u64)
            .map(|n| (n * 1024 * 1024).clamp(1024 * 1024, MAX_BYTES_HARD))
            .unwrap_or(MAX_BYTES),
        ..Default::default()
    };
    let cancel = CancellationToken::new();
    *lock(&core.import_cancel) = Some(cancel.clone());
    let emit = |done: usize, total: usize, stage: &str, name: &str| {
        core.emit(
            json!({ "type": "import", "project": project, "stage": stage,
            "done": done, "total": total, "name": name }),
        );
    };

    // Collect inputs (paths are read one by one under the budget).
    let mut items: Vec<Item> = Vec::new();
    let mut warn: Vec<Value> = Vec::new();
    let inputs: Vec<&str> = a
        .get("paths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    for p in input_files(&inputs, &mut budget) {
        let p = p.as_path();
        let name = label(&p.to_string_lossy());
        let meta = match std::fs::metadata(p) {
            Ok(m) if m.is_file() => m,
            _ => {
                budget.skip(&name, "not_a_file");
                continue;
            }
        };
        if meta.len() > MAX_FILE || budget.bytes + meta.len() > budget.max_bytes {
            budget.skip(&name, "file_too_large");
            continue;
        }
        match std::fs::read(p) {
            Ok(bytes) => expand(
                Item {
                    name,
                    source: "offline".into(),
                    bytes,
                    container: false,
                },
                0,
                &mut budget,
                &mut items,
                &mut warn,
            ),
            Err(e) => warn.push(json!({ "name": name, "error": e.to_string() })),
        }
    }
    for f in a
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = label(f["name"].as_str().unwrap_or("file"));
        let Some(bytes) = f["data"].as_str().and_then(foca_core::b64::decode) else {
            budget.skip(&name, "bad_data");
            continue;
        };
        expand(
            Item {
                name,
                source: "offline".into(),
                bytes,
                container: false,
            },
            0,
            &mut budget,
            &mut items,
            &mut warn,
        );
    }

    // Store and parse.
    let dir = core.cfg.data_dir.join("files").join(&project).join("files");
    std::fs::create_dir_all(&dir)?;
    let total = items.len();
    let mut ids: Vec<u64> = Vec::new();
    let mut duplicates = 0usize;
    let mut errors: Vec<Value> = warn;
    let mut cancelled = false;
    let ocr_cfg = crate::services::ocr::OcrSettings::from_settings(
        &core.store().settings_get().unwrap_or_default(),
    );
    let ocr_prov = core.current_ocr();
    for (i, it) in items.into_iter().enumerate() {
        if cancel.is_cancelled() {
            cancelled = true;
            break;
        }
        emit(i, total, "parse", &it.name);
        let sha = util::hex(&util::sha256(&it.bytes));
        let dst = dir.join(format!("{sha}.{}", safe_ext(&it.name)));
        if !dst.exists() {
            std::fs::write(&dst, &it.bytes)?;
        }
        let added = lock(&db).add_document(&AddDoc {
            url: None,
            name: it.name.clone(),
            source: it.source.clone(),
            status: DocStatus::Downloaded,
            size: it.bytes.len() as u64,
            sha256: Some(sha),
            local_path: Some(dst.to_string_lossy().into_owned()),
            ..Default::default()
        })?;
        if added.existing {
            duplicates += 1;
            continue;
        }
        let name = it.name.clone();
        let container = it.container;
        let dst_ocr = dst.clone();
        let ocr_c = ocr_cfg.clone();
        let ocr_p = ocr_prov.clone();
        let job = tokio::task::spawn_blocking(move || {
            let (m, mut t) = parse_one(&it.bytes, &it.name, container)?;
            if let Some(ot) = crate::services::ocr::maybe_ocr(
                &ocr_c,
                ocr_p.as_deref(),
                &dst_ocr,
                &it.name,
                &it.bytes,
                t.as_deref(),
            ) {
                t = Some(ot);
            }
            Ok((m, t))
        });
        let r = match tokio::time::timeout(FILE_TIMEOUT, job).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => Err(e.to_string()),
            // The blocking task keeps its bounded budget and ends on its own; the document
            // is marked and the import moves on.
            Err(_) => Err("timeout".to_string()),
        };
        let d = lock(&db);
        match r {
            Ok((m, t)) => d.set_analyzed(added.id, &m, t.as_deref())?,
            Err(e) => {
                errors.push(json!({ "name": name, "error": e }));
                d.set_doc_error(added.id, &e)?;
            }
        }
        ids.push(added.id);
    }
    emit(total, total, "analysis", "");
    {
        let db = db.clone();
        tokio::task::spawn_blocking(move || crate::analysis::insights::reanalyze(&lock(&db), None))
            .await
            .map_err(CmdError::internal)??;
    }
    emit(total, total, "done", "");
    *lock(&core.import_cancel) = None;
    Ok(json!({
        "project": project,
        "imported": ids.len(),
        "ids": ids,
        "duplicates": duplicates,
        "skipped": budget.skipped,
        "errors": errors,
        "cancelled": cancelled,
        "bytes": budget.bytes,
    }))
}

/// `import_cancel {}`: stops a running offline import after the current file.
pub(crate) fn import_cancel(core: &Core) -> CmdResult {
    let t = lock(&core.import_cancel).clone();
    if let Some(t) = &t {
        t.cancel();
    }
    Ok(json!({ "ok": t.is_some() }))
}

/// `docs_search { project, q, limit?, offset?, include_deleted? }` → `SearchPage`.
pub(crate) fn docs_search(core: &Core, a: &Value) -> CmdResult {
    let id = core.project_arg(a)?;
    let q = arg_str(a, "q").unwrap_or("");
    let mut o = SearchOpts::default();
    if let Some(n) = a.get("limit").and_then(Value::as_u64) {
        o.limit = n as usize;
    }
    if let Some(n) = a.get("offset").and_then(Value::as_u64) {
        o.offset = n as usize;
    }
    if let Some(b) = a.get("include_deleted").and_then(Value::as_bool) {
        o.include_deleted = b;
    }
    let db = core.db(&id)?;
    let page = lock(&db).search_text(q, &o)?;
    Ok(serde_json::to_value(page)?)
}

/// `rules_get { project }` → `{ presets, config }`.
pub(crate) fn rules_get(core: &Core, a: &Value) -> CmdResult {
    let id = core.project_arg(a)?;
    let db = core.db(&id)?;
    let cfg = lock(&db).rules_config()?;
    Ok(json!({ "presets": rules::presets(), "config": cfg }))
}

/// `rules_set { project, presets, rules }` → the stored `RulesConfig`; findings are
/// recomputed with the new rules.
pub(crate) fn rules_set(core: &Core, a: &Value) -> CmdResult {
    let id = core.project_arg(a)?;
    let cfg: RulesConfig = serde_json::from_value(a.get("config").cloned().unwrap_or_else(|| {
        json!({ "presets": a.get("presets").cloned().unwrap_or(json!([])),
                "rules": a.get("rules").cloned().unwrap_or(json!([])) })
    }))?;
    let db = core.db(&id)?;
    let db = lock(&db);
    db.set_rules_config(&cfg)?;
    let fresh = crate::analysis::insights::reanalyze(&db, None)?;
    Ok(json!({ "config": db.rules_config()?, "new_findings": fresh.len() }))
}

/// `rules_test { pattern, case_insensitive?, text }` → `{ count, hits: [{ start, end, value }] }`
/// (values masked; offsets let the UI highlight the caller's own text).
pub(crate) fn rules_test(a: &Value) -> CmdResult {
    let pattern = arg_str(a, "pattern").unwrap_or("");
    let text = arg_str(a, "text").unwrap_or("");
    if text.len() > 64 * 1024 {
        return Err(CmdError::new("bad_args", "текст длиннее 64 КиБ"));
    }
    let cfg = RulesConfig {
        presets: vec![],
        rules: vec![UserRule {
            id: "test".into(),
            title: "test".into(),
            pattern: pattern.into(),
            sev: Severity::Info,
            enabled: true,
            case_insensitive: a
                .get("case_insensitive")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            mask: true,
        }],
    };
    let rs = RuleSet::compile(&cfg).map_err(|e| {
        CmdError::new(
            "bad_args",
            e.iter()
                .map(|x| x.message.clone())
                .collect::<Vec<_>>()
                .join("; "),
        )
    })?;
    let hits: Vec<Value> = rs
        .scan(text, "текст")
        .iter()
        .map(|h| {
            json!({ "start": h.start, "end": h.end,
                    "value": foca_analysis::pii::pii_mask(h.value.expose()) })
        })
        .collect();
    Ok(json!({ "count": hits.len(), "hits": hits }))
}

/// `doc_get { project, id }` → `{ doc, format, forensics }`: the document card plus the 1.3
/// forensic details (signatures and qualified certificates, redactions, hidden content,
/// revisions, XMP history, PII summary, links, format fields). Secrets and personal values
/// are masked (`{{s:…}}`).
pub(crate) fn doc_get(core: &Core, a: &Value) -> CmdResult {
    let id = core.project_arg(a)?;
    let doc_id = a
        .get("id")
        .or_else(|| a.get("doc"))
        .and_then(Value::as_u64)
        .ok_or_else(|| CmdError::new("bad_args", "нужен id документа"))?;
    let db = core.db(&id)?;
    let db = lock(&db);
    let stored = db.document(doc_id)?;
    let card = db.ui_docs()?.into_iter().find(|d| d.id == doc_id);
    let Some(m) = stored.doc.metadata.as_ref() else {
        return Ok(json!({ "doc": card, "format": Value::Null, "forensics": Value::Null }));
    };
    let red = |s: &str| foca_analysis::pii::redact(s).0;
    let fields: serde_json::Map<String, Value> = m
        .fields
        .iter()
        .filter(|(k, _)| {
            [
                "lnk:",
                "eml:",
                "msg:",
                "ics:",
                "vcf:",
                "media:",
                "zip:",
                "visio:",
                "xl:connection:",
                "xl:pivotCache",
                "chart:",
                "wpd:",
                "pub:",
                "indd:",
            ]
            .iter()
            .any(|p| k.starts_with(p))
        })
        .take(300)
        .map(|(k, v)| (k.clone(), json!(red(v))))
        .collect();
    let mut fx = serde_json::Map::new();
    fx.insert("signatures".into(), serde_json::to_value(&m.signatures)?);
    fx.insert(
        "bad_redactions".into(),
        json!(m
            .bad_redactions
            .iter()
            .map(
                |r| json!({ "page": r.page, "fill": r.fill, "rect": r.rect, "text": red(&r.text) })
            )
            .collect::<Vec<_>>()),
    );
    fx.insert(
        "hidden_content".into(),
        json!(m
            .hidden_content
            .iter()
            .map(|h| json!({ "kind": h.kind, "location": h.location, "text": red(&h.text) }))
            .collect::<Vec<_>>()),
    );
    fx.insert(
        "pdf_revisions".into(),
        json!(m
            .pdf_revisions
            .iter()
            .map(|r| {
                let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
                for k in ["removed_text", "added_text"] {
                    if let Some(a) = v[k].as_array_mut() {
                        for x in a.iter_mut() {
                            *x = json!(red(x.as_str().unwrap_or("")));
                        }
                    }
                }
                v
            })
            .collect::<Vec<_>>()),
    );
    fx.insert("scan_without_text".into(), json!(m.scan_without_text));
    // document facts for the card: language, paper, file identifier, author time zone,
    // Office release and OS language hint (null when the format has none)
    let f = |k: &str| m.fields.get(k).cloned();
    fx.insert(
        "facts".into(),
        json!({
            "language": m.language.clone().or_else(|| f("pdf:Lang")),
            "page_size": f("pdf:page_size"),
            "paper": f("pdf:paper"),
            "tagged": m.fields.get("pdf:tagged").map(|v| v == "true"),
            "file_id": f("pdf:ID"),
            "tz_offset": f("doc:tz_offset"),
            "office_release": f("office:release"),
            "app_version": f("ole:AppVersion").or_else(|| f("app:AppVersion")),
            "locale_hint": f("os:locale_hint"),
            "code_page": f("ole:CodePage"),
        }),
    );
    fx.insert("xmp_history".into(), serde_json::to_value(&m.xmp_history)?);
    fx.insert("xmp_ids".into(), serde_json::to_value(&m.xmp_ids)?);
    fx.insert("pii".into(), serde_json::to_value(&m.pii)?);
    let geo: Vec<&foca_core::GeoPoint> = m.geo_points.iter().take(200).collect();
    fx.insert("geo_points".into(), serde_json::to_value(&geo)?);
    fx.insert(
        "ai_generated".into(),
        serde_json::to_value(&m.ai_generated)?,
    );
    fx.insert("connections".into(), serde_json::to_value(&m.connections)?);
    fx.insert("mail_hops".into(), serde_json::to_value(&m.mail_hops)?);
    fx.insert("fonts".into(), serde_json::to_value(&m.fonts)?);
    // form values can hold personal data: masked like the other document texts
    fx.insert(
        "form_fields".into(),
        json!(m
            .form_fields
            .iter()
            .map(|f| json!({ "name": red(&f.name), "value": f.value.as_deref().map(red) }))
            .collect::<Vec<_>>()),
    );
    let mut links: Vec<Value> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let found = stored
        .text
        .as_deref()
        .map(foca_analysis::links::interesting)
        .unwrap_or_default()
        .into_iter()
        .chain(
            m.links
                .iter()
                .filter_map(|l| foca_analysis::links::classify(l)),
        );
    for h in found {
        if (h.service.is_some() || !h.tokens.is_empty()) && seen.insert(h.url.clone()) {
            links.push(json!({ "url": h.url, "host": h.host, "service": h.service,
                "shared": h.shared, "internal": h.internal, "expires": h.expires,
                "tokens": h.tokens.iter().map(|t| json!({ "name": t.name, "kind": t.kind })).collect::<Vec<_>>(),
                "sev": h.sev }));
        }
        if links.len() >= 100 {
            break;
        }
    }
    fx.insert("links".into(), json!(links));
    fx.insert("fields".into(), Value::Object(fields));
    fx.insert(
        "embedded".into(),
        json!(m
            .embedded
            .iter()
            .take(100)
            .map(|e| json!({ "name": e.name, "format": e.metadata.format }))
            .collect::<Vec<_>>()),
    );
    Ok(json!({ "doc": card, "format": m.format, "forensics": fx }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_never_paths() {
        assert_eq!(label("../../etc/passwd"), "passwd");
        assert_eq!(label("a\\..\\b.docx"), "b.docx");
        assert_eq!(label("/"), "file");
        assert_eq!(label("x/<img onerror>.pdf"), "img onerror.pdf");
        assert_eq!(safe_ext("a.<b>"), "bin");
        assert_eq!(safe_ext("Report.PDF"), "pdf");
    }
}
