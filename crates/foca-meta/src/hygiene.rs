//! Document hygiene grade (A-F) with concrete fix steps.
//!
//! Pure functions over extracted [`Metadata`]: every finding becomes a [`HygieneIssue`] with a
//! severity, a count and one [`FixStep`] (a stable code plus parameters; user-facing texts are
//! resolved by the UI through i18n). Penalties per severity: critical 40, high 20, medium 10,
//! low 4, info 0; the score is `100 − Σ penalties` (floor 0). Thresholds: A ≥ 90, B ≥ 75,
//! C ≥ 60, D ≥ 40, E ≥ 20, F below. Any critical issue caps the grade at E. Signatures are
//! neutral (info): they prove origin but are lost on cleaning.

use std::collections::BTreeMap;

use foca_core::{DocFormat, Metadata, PathKind, PersonRole, Severity};
use serde::{Deserialize, Serialize};

use crate::clean::can_clean;

/// Hygiene grade, best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    E,
    F,
}

impl Grade {
    /// Grade for a score in `0..=100`.
    #[must_use]
    pub fn from_score(score: u8) -> Grade {
        match score {
            90.. => Grade::A,
            75..=89 => Grade::B,
            60..=74 => Grade::C,
            40..=59 => Grade::D,
            20..=39 => Grade::E,
            _ => Grade::F,
        }
    }

    fn better(self) -> Grade {
        match self {
            Grade::A | Grade::B => Grade::A,
            Grade::C => Grade::B,
            Grade::D => Grade::C,
            Grade::E => Grade::D,
            Grade::F => Grade::E,
        }
    }
}

/// What was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueCode {
    /// Author, editor, printed-by and other person names in metadata.
    People,
    /// Company or manager.
    Company,
    /// Local paths in metadata (`C:\Users\…`, `/home/…`, `file://`).
    LocalPaths,
    /// UNC paths and server names (internal infrastructure).
    NetworkPaths,
    /// Hyperlinks and paths in the document body pointing to internal resources.
    InternalLinks,
    Printers,
    Emails,
    /// Software names and versions.
    Software,
    /// Creation/modification dates, editing time and revision counter.
    EditHistory,
    CustomProperties,
    /// PDF incremental updates (older revisions are recoverable).
    PdfRevisions,
    /// Text removed in a later PDF revision is still in the file.
    PdfRemovedText,
    /// Text under an opaque box is still selectable.
    BadRedaction,
    /// Hidden text, rows, columns or sheets.
    HiddenContent,
    Comments,
    TrackedChanges,
    Gps,
    Camera,
    /// Embedded thumbnail differs from the image (pre-crop/pre-redaction content).
    ThumbnailMismatch,
    Thumbnail,
    /// XMP edit history and document IDs (link copies of the same file).
    XmpHistory,
    /// Word editing session identifiers.
    Rsids,
    EmbeddedFiles,
    Macros,
    Javascript,
    /// Personal data in the text.
    Pii,
    /// Credentials or keys in the document.
    Secrets,
    /// The document is digitally signed (neutral; cleaning removes the signature).
    Signed,
    /// Encrypted document: the assessment is incomplete.
    Encrypted,
}

/// How to fix an issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixCode {
    /// Run the cleaner ("share a clean copy").
    CleanMetadata,
    /// Rewrite the PDF without older revisions (the cleaner does this).
    RewritePdf,
    /// Remove the content for real (redaction tool), then rewrite the PDF.
    RedactProperly,
    RemoveHiddenContent,
    /// Edit or remove body hyperlinks to internal resources (the cleaner keeps content).
    ReviewLinks,
    ResolveComments,
    AcceptTrackedChanges,
    RegenerateThumbnail,
    RemoveEmbeddedFiles,
    RemoveMacros,
    RemoveJavascript,
    ReviewPii,
    RevokeSecret,
    /// Sign the clean copy again if a signature is required.
    ResignAfterCleaning,
    DecryptToAssess,
    /// The format cannot be cleaned here: export to PDF/ODF/OOXML and clean the export.
    ExportAndClean,
}

/// A fix step: code, parameters for the localized text, and whether the cleaner applies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixStep {
    pub code: FixCode,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    /// `true` if [`crate::clean_with_options`] fixes it for this format.
    pub auto: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HygieneIssue {
    pub code: IssueCode,
    pub severity: Severity,
    pub count: u32,
    /// Up to three examples (names, paths, kinds); empty for content-sensitive issues.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub samples: Vec<String>,
    pub fix: FixStep,
}

/// Hygiene of one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HygieneReport {
    pub grade: Grade,
    pub score: u8,
    pub format: DocFormat,
    /// The format can be cleaned automatically.
    pub cleanable: bool,
    /// Sorted by severity, most severe first.
    pub issues: Vec<HygieneIssue>,
}

/// Hygiene of a set of documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetHygiene {
    pub grade: Grade,
    /// Mean document score.
    pub score: u8,
    pub documents: u32,
    pub worst: Option<Grade>,
    /// Number of documents per grade.
    pub by_grade: BTreeMap<Grade, u32>,
    /// Issues by number of affected documents, most frequent and severe first.
    pub issues: Vec<SetIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetIssue {
    pub code: IssueCode,
    pub severity: Severity,
    pub documents: u32,
    pub fix: FixCode,
}

fn penalty(s: Severity) -> u32 {
    match s {
        Severity::Critical => 40,
        Severity::High => 20,
        Severity::Medium => 10,
        Severity::Low => 4,
        Severity::Info => 0,
    }
}

struct Builder {
    auto: bool,
    issues: Vec<HygieneIssue>,
}

impl Builder {
    /// `fix` is the step and whether the cleaner applies it for cleanable formats.
    fn add(
        &mut self,
        code: IssueCode,
        severity: Severity,
        count: usize,
        mut samples: Vec<String>,
        fix: (FixCode, bool),
        params: &[(&str, String)],
    ) {
        if count == 0 {
            return;
        }
        samples.dedup();
        samples.truncate(3);
        let (mut fix_code, auto) = fix;
        if fix_code == FixCode::CleanMetadata && !self.auto {
            fix_code = FixCode::ExportAndClean;
        }
        self.issues.push(HygieneIssue {
            code,
            severity,
            count: u32::try_from(count).unwrap_or(u32::MAX),
            samples,
            fix: FixStep {
                code: fix_code,
                params: params
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), v.clone()))
                    .collect(),
                auto: auto && self.auto,
            },
        });
    }
}

/// Grades one document from its extracted metadata and forensics.
#[must_use]
pub fn grade_document(m: &Metadata) -> HygieneReport {
    let cleanable = can_clean(m.format);
    let pdf = m.format == DocFormat::Pdf;
    let mut b = Builder {
        auto: cleanable,
        issues: Vec::new(),
    };
    use FixCode as F;
    use IssueCode as I;
    use Severity as S;

    let content = crate::verify::ContentRefs::new(m);
    let people: Vec<String> = m
        .people
        .iter()
        .filter(|p| match p.role {
            PersonRole::Comment | PersonRole::Revision => false,
            PersonRole::PathUser => !content.path(&p.source),
            _ => true,
        })
        .map(|p| p.name.clone())
        .collect();
    let mut uniq = people.clone();
    uniq.sort();
    uniq.dedup();
    b.add(
        I::People,
        S::High,
        uniq.len(),
        people,
        (F::CleanMetadata, true),
        &[],
    );
    let company: Vec<String> = [&m.company, &m.manager]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    b.add(
        I::Company,
        S::Medium,
        company.len(),
        company,
        (F::CleanMetadata, true),
        &[],
    );

    let (body_paths, meta_paths): (Vec<_>, Vec<_>) =
        m.paths.iter().partition(|p| content.path(&p.path));
    let (unc, local): (Vec<_>, Vec<_>) = meta_paths
        .into_iter()
        .partition(|p| p.kind == PathKind::Unc);
    b.add(
        I::LocalPaths,
        S::Medium,
        local.len(),
        local.iter().map(|p| p.path.clone()).collect(),
        (F::CleanMetadata, true),
        &[],
    );
    let mut hosts: Vec<String> = unc.iter().filter_map(|p| p.host.clone()).collect();
    let servers: Vec<&str> = m
        .servers
        .iter()
        .filter(|s| !(s.source == "path" && content.host_only_in_content(&s.name)))
        .map(|s| s.name.as_str())
        .collect();
    hosts.extend(servers.iter().map(|s| (*s).to_string()));
    hosts.sort();
    hosts.dedup();
    b.add(
        I::NetworkPaths,
        S::High,
        hosts.len().max(unc.len()),
        hosts,
        (F::CleanMetadata, true),
        &[],
    );
    let internal: Vec<String> = body_paths.iter().map(|p| p.path.clone()).collect();
    let internal_sev = if body_paths.iter().any(|p| p.kind == PathKind::Unc) {
        S::Medium
    } else {
        S::Low
    };
    b.add(
        I::InternalLinks,
        internal_sev,
        internal.len(),
        internal,
        (F::ReviewLinks, false),
        &[],
    );
    b.add(
        I::Printers,
        S::Medium,
        m.printers.len(),
        m.printers.clone(),
        (F::CleanMetadata, true),
        &[],
    );
    b.add(
        I::Emails,
        S::Medium,
        m.emails.len(),
        m.emails.clone(),
        (F::CleanMetadata, true),
        &[],
    );
    b.add(
        I::Software,
        S::Low,
        m.software.len(),
        m.software.clone(),
        (F::CleanMetadata, true),
        &[],
    );
    let history = usize::from(m.created.is_some() || m.modified.is_some() || m.printed.is_some())
        + usize::from(m.edit_time_secs.is_some() || m.revision.is_some());
    b.add(
        I::EditHistory,
        S::Low,
        history,
        Vec::new(),
        (F::CleanMetadata, true),
        &[],
    );
    b.add(
        I::CustomProperties,
        S::Low,
        m.custom.len(),
        m.custom.keys().cloned().collect(),
        (F::CleanMetadata, true),
        &[],
    );

    let updates = m.incremental_updates.unwrap_or(0) as usize;
    let revs = updates
        .max(m.old_versions.len())
        .max(m.pdf_revisions.len().saturating_sub(1));
    b.add(
        I::PdfRevisions,
        S::High,
        revs,
        Vec::new(),
        (F::RewritePdf, pdf),
        &[("count", revs.to_string())],
    );
    let removed: usize = m.pdf_revisions.iter().map(|r| r.removed_text.len()).sum();
    b.add(
        I::PdfRemovedText,
        S::Critical,
        removed,
        Vec::new(),
        (F::RewritePdf, pdf),
        &[("count", removed.to_string())],
    );
    let mut pages: Vec<u32> = m.bad_redactions.iter().map(|r| r.page).collect();
    pages.sort_unstable();
    pages.dedup();
    let pages_s = pages
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    b.add(
        I::BadRedaction,
        S::Critical,
        m.bad_redactions.len(),
        Vec::new(),
        (F::RedactProperly, false),
        &[("pages", pages_s)],
    );
    let hidden = m.hidden_content.len() + m.hidden_sheets.len();
    b.add(
        I::HiddenContent,
        S::Medium,
        hidden,
        m.hidden_sheets.clone(),
        (F::RemoveHiddenContent, false),
        &[],
    );
    b.add(
        I::Comments,
        S::Medium,
        m.comments.len(),
        Vec::new(),
        (F::ResolveComments, false),
        &[("count", m.comments.len().to_string())],
    );
    b.add(
        I::TrackedChanges,
        S::Medium,
        m.revisions.len(),
        Vec::new(),
        (F::AcceptTrackedChanges, false),
        &[("count", m.revisions.len().to_string())],
    );
    let embedded_gps = m
        .embedded
        .iter()
        .filter(|e| e.metadata.gps.is_some())
        .count();
    b.add(
        I::Gps,
        S::High,
        usize::from(m.gps.is_some()) + embedded_gps,
        Vec::new(),
        (F::CleanMetadata, true),
        &[],
    );
    let camera = m
        .camera
        .as_ref()
        .map_or(0, |c| usize::from(c.make.is_some() || c.model.is_some()));
    b.add(
        I::Camera,
        S::Low,
        camera,
        Vec::new(),
        (F::CleanMetadata, true),
        &[],
    );
    match &m.thumbnail {
        Some(t) if t.differs == Some(true) => b.add(
            I::ThumbnailMismatch,
            S::High,
            1,
            Vec::new(),
            (F::RegenerateThumbnail, true),
            &[],
        ),
        Some(_) => b.add(
            I::Thumbnail,
            S::Low,
            1,
            Vec::new(),
            (F::CleanMetadata, true),
            &[],
        ),
        None => {}
    }
    let xmp = m.xmp_history.len() + usize::from(m.xmp_ids.is_some());
    b.add(
        I::XmpHistory,
        S::Low,
        xmp,
        Vec::new(),
        (F::CleanMetadata, true),
        &[],
    );
    b.add(
        I::Rsids,
        S::Low,
        usize::from(!m.rsids.is_empty()),
        Vec::new(),
        (F::CleanMetadata, true),
        &[],
    );
    let files = m.attachments.len().max(
        m.embedded
            .iter()
            .filter(|e| !e.name.starts_with("Pictures/") && !e.name.contains("/media/"))
            .count(),
    );
    b.add(
        I::EmbeddedFiles,
        S::Medium,
        files,
        m.attachments.iter().map(|a| a.name.clone()).collect(),
        (F::RemoveEmbeddedFiles, pdf),
        &[("count", files.to_string())],
    );
    b.add(
        I::Macros,
        S::Medium,
        usize::from(m.has_macros),
        m.macro_modules.clone(),
        (F::RemoveMacros, false),
        &[],
    );
    b.add(
        I::Javascript,
        S::Medium,
        usize::from(m.has_javascript),
        Vec::new(),
        (F::RemoveJavascript, pdf),
        &[],
    );
    if let Some(worst) = m.pii.iter().map(|p| p.sev).min() {
        let mut kinds: Vec<String> = m.pii.iter().map(|p| p.kind.clone()).collect();
        kinds.sort();
        kinds.dedup();
        let n: u32 = m.pii.iter().map(|p| p.count).sum();
        let sev = if worst == S::Critical { S::High } else { worst };
        b.add(
            I::Pii,
            sev,
            n as usize,
            kinds.clone(),
            (F::ReviewPii, false),
            &[("kinds", kinds.join(", "))],
        );
    }
    let mut skinds: Vec<String> = m.secrets.iter().map(|s| s.kind.clone()).collect();
    skinds.sort();
    skinds.dedup();
    b.add(
        I::Secrets,
        S::Critical,
        m.secrets.len(),
        skinds.clone(),
        (F::RevokeSecret, false),
        &[("kinds", skinds.join(", "))],
    );
    b.add(
        I::Signed,
        S::Info,
        m.signatures.len(),
        Vec::new(),
        (F::ResignAfterCleaning, false),
        &[],
    );
    b.add(
        I::Encrypted,
        S::Info,
        usize::from(m.encrypted),
        Vec::new(),
        (F::DecryptToAssess, false),
        &[],
    );

    let mut issues = b.issues;
    issues.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.code.cmp(&b.code)));
    let total: u32 = issues.iter().map(|i| penalty(i.severity)).sum();
    let score = u8::try_from(100u32.saturating_sub(total)).unwrap_or(0);
    let mut grade = Grade::from_score(score);
    if issues.iter().any(|i| i.severity == S::Critical) {
        grade = grade.max(Grade::E);
    }
    HygieneReport {
        grade,
        score,
        format: m.format,
        cleanable,
        issues,
    }
}

/// Aggregates document reports: mean score, but never more than one grade better than the
/// worst document.
#[must_use]
pub fn grade_set(reports: &[HygieneReport]) -> SetHygiene {
    let n = reports.len();
    let mut by_grade = BTreeMap::new();
    let mut agg: BTreeMap<IssueCode, (Severity, u32, FixCode)> = BTreeMap::new();
    for r in reports {
        *by_grade.entry(r.grade).or_insert(0) += 1;
        for i in &r.issues {
            let e = agg.entry(i.code).or_insert((i.severity, 0, i.fix.code));
            e.0 = e.0.min(i.severity);
            e.1 += 1;
        }
    }
    let worst = reports.iter().map(|r| r.grade).max();
    let sum: usize = reports.iter().map(|r| usize::from(r.score)).sum();
    let score = sum
        .checked_div(n)
        .map_or(100, |m| u8::try_from(m).unwrap_or(0));
    let mut grade = Grade::from_score(score);
    if let Some(w) = worst {
        grade = grade.max(w.better());
    }
    let mut issues: Vec<SetIssue> = agg
        .into_iter()
        .map(|(code, (severity, documents, fix))| SetIssue {
            code,
            severity,
            documents,
            fix,
        })
        .collect();
    issues.sort_by(|a, b| {
        b.documents
            .cmp(&a.documents)
            .then(a.severity.cmp(&b.severity))
    });
    SetHygiene {
        grade,
        score,
        documents: u32::try_from(n).unwrap_or(u32::MAX),
        worst,
        by_grade,
        issues,
    }
}
