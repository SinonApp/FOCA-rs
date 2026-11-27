//! Cleaning self-check: the clean copy is parsed again with [`crate::extract`], its fields are
//! diffed against the original, and the verdict is "valid file with no identifying metadata".

use std::collections::BTreeMap;
use std::io::Cursor;

use foca_core::{DocFormat, Metadata, PersonRole};
use serde::{Deserialize, Serialize};

use crate::clean::{clean_with_options, CleanOptions, CleanWarning};
use crate::{detect, extract, Limits, MetaError};

/// How a field changed between the original and the clean copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Removed,
    Changed,
    Kept,
    Added,
}

/// One row of the before/after diff. Multiple values of a field are joined with `"; "`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldChange {
    /// Field path: `author`, `people.author`, `xmp.dc:creator`, `embedded[Pictures/a.jpg].gps`.
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    pub change: ChangeKind,
    /// Identifying metadata (counts towards the verdict); `false` for document content and
    /// structure (statistics, links, comment text, hidden content).
    pub sensitive: bool,
}

/// Result of the self-check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// The clean copy parses, has the expected format and keeps its structure (PDF page count
    /// and a single revision; ODF `mimetype` first and stored).
    pub valid: bool,
    /// Why the copy is not valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Sensitive fields still present in the clean copy.
    pub remaining: usize,
    /// `valid && remaining == 0`.
    pub clean: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pages_before: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pages_after: Option<u64>,
    /// PDF: page text (content streams) is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_preserved: Option<bool>,
    pub changes: Vec<FieldChange>,
    pub warnings: Vec<CleanWarning>,
}

/// Clean copy with its self-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanResult {
    pub bytes: Vec<u8>,
    pub report: VerifyReport,
}

/// Cleans a document and verifies the result (see [`verify_clean`]).
///
/// # Errors
///
/// Returns the cleaning error; verification problems are reported in [`VerifyReport`].
pub fn clean_and_verify(
    bytes: &[u8],
    kind: DocFormat,
    opts: &CleanOptions,
    limits: &Limits,
) -> Result<CleanResult, MetaError> {
    let out = clean_with_options(bytes, kind, opts, limits)?;
    let mut report = verify_clean(bytes, &out.bytes, kind, limits);
    report.warnings = out.warnings;
    Ok(CleanResult {
        bytes: out.bytes,
        report,
    })
}

/// Compares the metadata of `original` and `cleaned`.
#[must_use]
pub fn verify_clean(
    original: &[u8],
    cleaned: &[u8],
    kind: DocFormat,
    limits: &Limits,
) -> VerifyReport {
    let before = extract(original, None, limits).ok();
    let after = extract(cleaned, None, limits);
    let mut report = VerifyReport {
        valid: true,
        error: None,
        remaining: 0,
        clean: false,
        pages_before: before.as_ref().and_then(|m| m.stats.get("pages").copied()),
        pages_after: None,
        text_preserved: None,
        changes: Vec::new(),
        warnings: Vec::new(),
    };
    let after = match after {
        Ok(m) => m,
        Err(e) => {
            report.valid = false;
            report.error = Some(format!("очищенный файл не читается: {e}"));
            if let Some(b) = &before {
                report.changes = diff(&flatten(b), &BTreeMap::new());
            }
            return report;
        }
    };
    report.pages_after = after.stats.get("pages").copied();
    let actual = detect(cleaned);
    let same_kind = actual == kind || (kind.is_ooxml() && actual.is_ooxml());
    let mut problems = Vec::new();
    if !same_kind {
        problems.push(format!("формат изменился: {kind:?} → {actual:?}"));
    }
    match kind {
        DocFormat::Pdf => {
            if report.pages_before.is_some() && report.pages_before != report.pages_after {
                problems.push("число страниц изменилось".into());
            }
            if after.incremental_updates.unwrap_or(0) > 0 {
                problems.push("остались инкрементальные ревизии".into());
            }
            let t0 = crate::text(original, limits).ok();
            let t1 = crate::text(cleaned, limits).ok();
            report.text_preserved = match (t0, t1) {
                (Some(a), Some(b)) => Some(page_text(&a) == page_text(&b)),
                _ => None,
            };
        }
        DocFormat::Odt | DocFormat::Ods | DocFormat::Odp | DocFormat::Odg => {
            if let Err(e) = check_odf_package(cleaned) {
                problems.push(e);
            }
        }
        _ => {}
    }
    if !problems.is_empty() {
        report.valid = false;
        report.error = Some(problems.join("; "));
    }
    let a = flatten(&after);
    report.changes = diff(&before.as_ref().map(flatten).unwrap_or_default(), &a);
    report.remaining = report
        .changes
        .iter()
        .filter(|c| c.sensitive && c.after.is_some())
        .count();
    report.clean = report.valid && report.remaining == 0;
    report
}

/// Non-empty text lines, order kept (annotation text of removed objects may disappear, so only
/// lines are compared as a multiset of the page text).
fn page_text(t: &str) -> Vec<String> {
    let mut v: Vec<String> = t
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    v.sort();
    v
}

/// ODF packaging rules: `mimetype` is the first entry, stored, without extra field.
fn check_odf_package(b: &[u8]) -> Result<(), String> {
    let mut z = zip::ZipArchive::new(Cursor::new(b)).map_err(|e| format!("ZIP: {e}"))?;
    let f = z.by_index_raw(0).map_err(|e| format!("ZIP: {e}"))?;
    if f.name().ok().as_deref() != Some("mimetype") {
        return Err("mimetype не первая запись".into());
    }
    if f.compression() != zip::CompressionMethod::Stored {
        return Err("mimetype сжат".into());
    }
    Ok(())
}

type Flat = BTreeMap<String, (Vec<String>, bool)>;

fn diff(before: &Flat, after: &Flat) -> Vec<FieldChange> {
    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .map(|k| {
            let b = before.get(k);
            let a = after.get(k);
            let join = |v: Option<&(Vec<String>, bool)>| v.map(|(x, _)| x.join("; "));
            let (bv, av) = (join(b), join(a));
            let change = match (&bv, &av) {
                (Some(x), Some(y)) if x == y => ChangeKind::Kept,
                (Some(_), Some(_)) => ChangeKind::Changed,
                (Some(_), None) => ChangeKind::Removed,
                _ => ChangeKind::Added,
            };
            FieldChange {
                field: k.clone(),
                before: bv,
                after: av,
                change,
                // the clean copy decides: a neutral replacement value is not sensitive
                sensitive: a.or(b).is_some_and(|(_, s)| *s),
            }
        })
        .collect()
}

/// `fields`/`xmp` keys that describe structure rather than identity.
fn structural_field(k: &str) -> bool {
    matches!(
        k,
        "pdf:version"
            | "pdf:acroform"
            | "pdf:Trapped"
            | "image:width"
            | "image:height"
            | "jfif:version"
            | "png:color_type"
            | "png:bit_depth"
            | "ole:Security"
            | "ole:CodePage"
            | "doc:lid"
            | "visio:file_version"
            | "pub:quill_version"
            | "media:major_brand"
            | "media:handler"
    ) || k.starts_with("image:")
        || k.starts_with("png:")
        // the colour profile stays so colours render the same; only the device model can name
        // a scanner or camera
        || (k.starts_with("icc:") && !k.starts_with("icc:device_model"))
        || matches!(k, "pdf:xfa" | "pdf:portfolio" | "pdf:OutputIntent")
        // page geometry, tagging and language describe layout
        || matches!(k, "pdf:page_size" | "pdf:paper" | "pdf:tagged" | "pdf:Lang")
        // hidden sheets are content (graded as hidden content), query text is content
        || k.starts_with("xl:veryHidden:")
        || k.starts_with("xl:hidden:")
        || (k.starts_with("xl:connection:") && k.ends_with(":command"))
        || (k.starts_with("xl:pivotCache")
            && [":refreshedVersion", ":source", ":connectionId"]
                .iter()
                .any(|s| k.ends_with(s)))
}

/// Flattens metadata into `field → (values, sensitive)`.
pub(crate) fn flatten(m: &Metadata) -> Flat {
    let mut f = Flat::new();
    flatten_into(m, "", &mut f, 0);
    f
}

fn flatten_into(m: &Metadata, prefix: &str, f: &mut Flat, depth: u32) {
    let mut put = |k: &str, v: String, sensitive: bool| {
        if v.trim().is_empty() {
            return;
        }
        let e = f
            .entry(format!("{prefix}{k}"))
            .or_insert_with(|| (Vec::new(), sensitive));
        if !e.0.contains(&v) && e.0.len() < 50 {
            e.0.push(v);
        }
    };
    for (k, v) in [
        ("title", &m.title),
        ("subject", &m.subject),
        ("description", &m.description),
        ("keywords", &m.keywords),
        ("category", &m.category),
        ("author", &m.author),
        ("last_modified_by", &m.last_modified_by),
        ("company", &m.company),
        ("manager", &m.manager),
        ("application", &m.application),
        ("producer", &m.producer),
        ("os", &m.os),
        ("revision", &m.revision),
        ("created", &m.created),
        ("modified", &m.modified),
        ("printed", &m.printed),
    ] {
        if let Some(v) = v {
            put(k, v.clone(), true);
        }
    }
    if let Some(v) = &m.template {
        // the OOXML cleaner points the attached template at the neutral default
        let neutral = matches!(v.as_str(), "Normal.dotm" | "Normal.dot" | "Normal");
        put("template", v.clone(), !neutral);
    }
    if let Some(v) = &m.language {
        put("language", v.clone(), false);
    }
    if let Some(s) = m.edit_time_secs {
        put("edit_time_secs", s.to_string(), true);
    }
    for (k, v) in &m.stats {
        put(&format!("stats.{k}"), v.to_string(), false);
    }
    for (k, v) in &m.custom {
        put(&format!("custom.{k}"), v.clone(), true);
    }
    let content = ContentRefs::new(m);
    for p in &m.people {
        let role = serde_plain(&p.role);
        let sensitive = p.role != PersonRole::PathUser || !content.path(&p.source);
        put(&format!("people.{role}"), p.name.clone(), sensitive);
    }
    for v in &m.emails {
        put("emails", v.clone(), !content.text_has(v));
    }
    for p in &m.paths {
        let key = if content.path(&p.path) {
            "content.paths"
        } else {
            "paths"
        };
        put(key, p.path.clone(), key == "paths");
    }
    for s in &m.servers {
        let key = if s.source == "path" && content.host_only_in_content(&s.name) {
            "content.servers"
        } else {
            "servers"
        };
        put(key, s.name.clone(), key == "servers");
    }
    for v in &m.printers {
        put("printers", v.clone(), true);
    }
    for v in &m.software {
        put("software", v.clone(), true);
    }
    for v in &m.links {
        put("links", v.clone(), false);
    }
    for s in &m.secrets {
        put("secrets", format!("{}: {}", s.kind, s.value), false);
    }
    for c in &m.comments {
        if let Some(a) = &c.author {
            put("comments.author", a.clone(), true);
        }
        put("comments.text", c.text.clone(), false);
    }
    for r in &m.revisions {
        if let Some(a) = &r.author {
            put("revisions.author", a.clone(), true);
        }
    }
    for v in &m.rsids {
        put("rsids", v.clone(), true);
    }
    for v in &m.hidden_sheets {
        put("hidden_sheets", v.clone(), false);
    }
    if m.has_macros {
        put("has_macros", "true".into(), false);
    }
    if m.has_javascript {
        put("has_javascript", "true".into(), false);
    }
    if let Some(n) = m.incremental_updates.filter(|n| *n > 0) {
        put("incremental_updates", n.to_string(), true);
    }
    for o in &m.old_versions {
        for (k, v) in &o.fields {
            put(&format!("old_versions.{k}"), v.clone(), true);
        }
    }
    for a in &m.attachments {
        put("attachments", a.name.clone(), false);
    }
    if let Some(g) = &m.gps {
        put("gps", format!("{:.6},{:.6}", g.lat, g.lon), true);
    }
    if let Some(c) = &m.camera {
        for (k, v) in [("make", &c.make), ("model", &c.model)] {
            if let Some(v) = v {
                put(&format!("camera.{k}"), v.clone(), true);
            }
        }
    }
    if let Some(t) = &m.thumbnail {
        put(
            "thumbnail",
            format!("{} ({} B)", t.mime, t.data.len()),
            true,
        );
    }
    for (k, v) in &m.xmp {
        put(&format!("xmp.{k}"), v.clone(), true);
    }
    for (k, v) in &m.fields {
        // the cleaner always writes a new content-derived file identifier
        if matches!(k.as_str(), "pdf:ID" | "pdf:ID_instance") {
            continue;
        }
        // an external workbook reference without a directory is a plain formula
        let bare_ref = k.starts_with("chart:")
            && k.ends_with(":externalRef")
            && !(v.contains(":\\") || v.contains("\\\\") || v.contains('/'));
        put(
            &format!("fields.{k}"),
            v.clone(),
            !structural_field(k) && !bare_ref,
        );
    }
    if !m.xmp_history.is_empty() {
        put("xmp_history", m.xmp_history.len().to_string(), true);
    }
    if let Some(ids) = &m.xmp_ids {
        for v in [
            &ids.document_id,
            &ids.instance_id,
            &ids.original_document_id,
        ]
        .into_iter()
        .flatten()
        {
            put("xmp_ids", v.clone(), true);
        }
    }
    for s in &m.signatures {
        let who = s
            .signer
            .as_ref()
            .and_then(|c| c.common_name.clone())
            .unwrap_or_else(|| s.source.clone());
        put("signatures", who, true);
    }
    if m.pdf_revisions.len() > 1 {
        put("pdf_revisions", m.pdf_revisions.len().to_string(), true);
    }
    for r in &m.bad_redactions {
        put("bad_redactions", format!("p.{}: {}", r.page, r.text), false);
    }
    for h in &m.hidden_content {
        put("hidden_content", format!("{}: {}", h.kind, h.text), false);
    }
    for p in &m.pii {
        put("pii", format!("{} ×{}", p.kind, p.count), false);
    }
    if depth < 3 {
        for e in &m.embedded {
            let p = format!("{prefix}embedded[{}].", e.name);
            flatten_into(&e.metadata, &p, f, depth + 1);
        }
    }
}

/// Paths, hosts and e-mails that come from the document body (hyperlinks, comment text,
/// tracked changes) rather than from metadata: the cleaner keeps content, so they do not count
/// against the verdict (the hygiene grade reports them separately).
pub(crate) struct ContentRefs<'m> {
    m: &'m Metadata,
}

impl<'m> ContentRefs<'m> {
    pub(crate) fn new(m: &'m Metadata) -> Self {
        ContentRefs { m }
    }

    fn content_source(&self, src: &str) -> bool {
        src == "link" || src == "revision" || self.m.comments.iter().any(|c| c.source == src)
    }

    /// True if path `p` was found only in document content.
    pub(crate) fn path(&self, p: &str) -> bool {
        self.m
            .paths
            .iter()
            .find(|x| x.path == p)
            .is_some_and(|x| self.content_source(&x.source))
    }

    pub(crate) fn host_only_in_content(&self, host: &str) -> bool {
        let mut with_host = self
            .m
            .paths
            .iter()
            .filter(|p| {
                p.host
                    .as_deref()
                    .is_some_and(|h| h.eq_ignore_ascii_case(host))
            })
            .peekable();
        with_host.peek().is_some() && with_host.all(|p| self.content_source(&p.source))
    }

    pub(crate) fn text_has(&self, v: &str) -> bool {
        self.m.links.iter().any(|l| l.contains(v))
            || self.m.comments.iter().any(|c| c.text.contains(v))
            || self.m.revisions.iter().any(|r| r.text.contains(v))
    }
}

/// Serde name of a unit enum variant (`PersonRole::LastModifiedBy` → `last_modified_by`).
fn serde_plain<T: Serialize + std::fmt::Debug>(v: &T) -> String {
    let dbg = format!("{v:?}");
    let mut out = String::with_capacity(dbg.len() + 4);
    for (i, c) in dbg.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}
