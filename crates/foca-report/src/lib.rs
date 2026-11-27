//! Reports and exports for FOCA-rs.
//!
//! * [`build_report`] builds a pentest report: self-contained HTML (inline CSS, no external
//!   resources or JS, A4), Markdown (Obsidian), CSV (RFC 4180, BOM) or JSON
//!   (`schema/report.v1.json`). Risk and counts cover only the findings included in the
//!   report; [`ResultSnapshot`] is the snapshot kept in history.
//! * [`export()`] exports tables: plain list, `.txt` wordlist, CSV, JSON, Maltego CSV, GraphML,
//!   Markdown.
//! * [`build_report_with_visuals`] adds static inline SVG diagrams ([`svg`]): link graph,
//!   internal network map, chronology and activity heat map.
//!
//! Security: every string from metadata is hostile input, and renderers emit it only through
//! [`safe`] (HTML/XML/Markdown/CSV escaping, CSV injection protection, safe file names and
//! links). Secrets are hidden by default ([`SecretMode::Hide`], `include_secrets = false`).

#![recursion_limit = "512"]

pub mod data;
pub mod export;
pub mod formats;
pub mod i18n;
pub mod mask;
pub mod opts;
pub mod safe;
pub mod svg;

mod ftext;
mod page;
mod recon_view;
mod sections;
mod table;
mod templates;

use std::collections::BTreeMap;

use foca_core::api::{Finding, Snapshot};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;

pub use data::{Counts, LogSummary, Overview, RequestEntry, ResultSnapshot};
pub use export::{export, export_with_log, Artifact};
pub use formats::logo::{self, LogoError, LogoImage, LOGO_MAX_BYTES, LOGO_MAX_SIDE};
/// Finding text in a language (`text`, `provenance.rule`, `lang`), as reports show it.
pub use ftext::translate as translate_finding_text;
pub use opts::{
    AiSummary, DictKind, ExportFormat, ExportKind, ExportOptions, Lang, Logo, MdLayout,
    ReportFormat, ReportOptions, SecretMode, Sections, Template, AI_SUMMARY_DATA_KEY,
};
pub use sections::custody;
pub use svg::Visuals;

/// Version of the report JSON schema (`schema/report.v1.json`).
pub const SCHEMA_VERSION: u32 = 1;
/// JSON report schema, embedded for validation and for handing out to users.
pub const REPORT_SCHEMA: &str = include_str!("../schema/report.v1.json");
/// Generator string (footer, front matter, JSON).
pub const GENERATOR: &str = concat!("FOCA-rs ", env!("CARGO_PKG_VERSION"));

/// Report figures for history and the "report ready" toast.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Counts per severity over the included findings (excluding false positives and fixed).
    pub counts: Counts,
    pub total: u32,
    /// Fixed findings (separate section).
    pub fixed: u32,
    /// Risk over the included findings; `None` if there is no data.
    pub risk: Option<u8>,
    pub risk_level: String,
    /// Project risk over all active findings (for comparison).
    pub project_risk: Option<u8>,
    pub pages: Option<u32>,
    pub docs: u32,
    pub people: u32,
    pub emails: u32,
    pub hosts: u32,
    pub software: u32,
    pub eol_software: u32,
    pub secrets: u32,
    pub requests: u32,
}

/// A finished report.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportArtifact {
    pub bytes: Vec<u8>,
    pub file_name: String,
    pub mime: &'static str,
    /// `N` from `_vN`.
    pub version: u32,
    /// Language for the history record: `RU`/`UA`/`EN`, or a dash for `csv/json`.
    pub lang: String,
    pub summary: ReportSummary,
    /// Result snapshot (`Report.result`); history shows it instead of the current data.
    pub results_snapshot: ResultSnapshot,
    /// Normalized options (what is stored in `Report.opts`).
    pub opts: Value,
}

impl ReportArtifact {
    /// Size label for `Report.size`, in the UI's Russian units (e.g. 12 KB, 1,4 MB).
    pub fn size_label(&self) -> String {
        size_label(self.bytes.len())
    }

    /// Builds the history record in the `Report` shape from `docs/API.md` (with `result`).
    pub fn report_record(&self, id: u64, created_at: &str, tpl_label: &str) -> Value {
        json!({
            "id": id,
            "name": self.file_name,
            "tpl": tpl_label,
            "fmt": self.file_name.rsplit('.').next().unwrap_or(""),
            "lang": self.lang,
            "created_at": created_at,
            "size": self.size_label(),
            "opts": self.opts,
            "result": self.results_snapshot,
        })
    }
}

/// Formats a byte count with Russian units: `1234` → 2 KB, `1_500_000` → 1,4 MB.
pub fn size_label(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} МБ", n as f64 / 1024.0 / 1024.0).replace('.', ",")
    } else {
        format!("{} КБ", n.div_ceil(1024).max(1))
    }
}

/// Returns the next version number: the highest `_vN` among the project's report names + 1.
pub fn next_version(snap: &Snapshot) -> u32 {
    snap.reports
        .iter()
        .filter_map(|r| {
            let stem = r.name.rsplit_once('.').map(|(s, _)| s).unwrap_or(&r.name);
            let (_, n) = stem.rsplit_once("_v")?;
            n.parse::<u32>().ok()
        })
        .max()
        .unwrap_or(0)
        + 1
}

/// Returns the report file name: `<localized prefix>_<project>_vN.html`, or
/// `Data_<project>_vN.<fmt>` for `csv/json`.
pub fn report_file_name(snap: &Snapshot, o: &ReportOptions, version: u32) -> String {
    let project = if snap.project.name.is_empty() {
        "project"
    } else {
        snap.project.name.as_str()
    };
    let prefix = if matches!(o.fmt, ReportFormat::Csv | ReportFormat::Json) {
        "Data"
    } else {
        i18n::file_prefix(o.lang)
    };
    safe::file_name_ext(&format!("{prefix}_{project}_v{version}"), o.fmt.ext())
}

/// Rendering context of one report.
pub(crate) struct Ctx<'a> {
    pub snap: &'a Snapshot,
    pub log: &'a [RequestEntry],
    pub o: &'a ReportOptions,
    pub t: &'static i18n::Strings,
    pub main: Vec<&'a Finding>,
    pub fixed: Vec<&'a Finding>,
    pub res: ResultSnapshot,
    pub ov: Overview,
    pub ls: LogSummary,
    pub red: mask::Redactor,
    pub now: OffsetDateTime,
    pub doc_names: BTreeMap<u64, String>,
    /// Diagram data with secrets already masked.
    pub vis: Visuals,
    /// Kind and value count of every `pii` finding, read from the source (Russian)
    /// texts before localization.
    pub pii: BTreeMap<u64, (&'static str, u64)>,
    /// Report number of every included finding: position in the severity-sorted active
    /// list, then the fixed list continues the sequence.
    pub num: BTreeMap<u64, usize>,
}

/// One block of the AI summary text, reduced to what every format can show safely.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum AiBlock {
    Head(String),
    Item(String),
    Para(String),
}

/// Upper bound for the AI summary in a report (characters).
const AI_SUMMARY_MAX: usize = 20_000;

/// Splits the model's Markdown into headings, list items and paragraphs as plain text
/// (emphasis/code markers dropped); every format escapes the text itself.
pub(crate) fn ai_blocks(md: &str) -> Vec<AiBlock> {
    let md: String = md.chars().take(AI_SUMMARY_MAX).collect();
    let plain = |s: &str| {
        s.replace("**", "")
            .replace("__", "")
            .replace('`', "")
            .trim()
            .to_string()
    };
    let mut out = Vec::new();
    let mut para: Vec<String> = Vec::new();
    let flush = |para: &mut Vec<String>, out: &mut Vec<AiBlock>| {
        if !para.is_empty() {
            out.push(AiBlock::Para(para.join(" ")));
            para.clear();
        }
    };
    for line in md.lines() {
        let l = line.trim();
        if l.is_empty() || l.chars().all(|c| matches!(c, '-' | '*' | '_' | '=')) {
            flush(&mut para, &mut out);
            continue;
        }
        if l.starts_with('#') {
            flush(&mut para, &mut out);
            let h = plain(l.trim_start_matches('#'));
            if !h.is_empty() {
                out.push(AiBlock::Head(h));
            }
            continue;
        }
        let item = l
            .strip_prefix("- ")
            .or_else(|| l.strip_prefix("* "))
            .or_else(|| l.strip_prefix("+ "))
            .map(str::to_string)
            .or_else(|| {
                let d = l.find(|c: char| !c.is_ascii_digit())?;
                (d > 0 && l[d..].starts_with(". ")).then(|| l.to_string())
            });
        match item {
            Some(it) => {
                flush(&mut para, &mut out);
                let it = plain(&it);
                if !it.is_empty() {
                    out.push(AiBlock::Item(it));
                }
            }
            None => para.push(plain(l.trim_start_matches('>'))),
        }
    }
    flush(&mut para, &mut out);
    out
}

/// Attribution of third-party vulnerability data shown in the report footer when findings use it
/// (FIRST asks to credit EPSS; Vulnrichment is CC0 but credited as well). Proper names, so the
/// line is the same in every report language.
pub const EPSS_CREDITS: &str =
    "EPSS: FIRST.org (https://www.first.org/epss) · CVSS/CWE: CISA Vulnrichment (CC0)";

impl Ctx<'_> {
    /// Footer attribution line for third-party data the included findings show.
    pub(crate) fn data_credits(&self) -> Option<&'static str> {
        self.main
            .iter()
            .chain(&self.fixed)
            .any(|f| f.evidence.contains(" EPSS "))
            .then_some(EPSS_CREDITS)
    }

    /// AI summary to render: stored, non-empty and not switched off in the options.
    pub fn ai_summary(&self) -> Option<&AiSummary> {
        self.o
            .ai_summary
            .as_ref()
            .filter(|a| self.o.include_ai_summary && !a.text.trim().is_empty())
    }
    /// Label line under the AI summary heading (who generated it and when).
    pub fn ai_summary_note(&self, a: &AiSummary) -> String {
        let src = [a.provider.as_str(), a.model.as_str()]
            .iter()
            .filter(|s| !s.trim().is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" · ");
        let date = a.created.get(..10).unwrap_or(&a.created);
        i18n::ai_summary_note(self.o.lang, &src, date)
    }
    /// Returns the string with secrets rendered according to the mode.
    pub fn r(&self, s: &str) -> String {
        self.red.text(s)
    }
    /// Returns the string for HTML: masked and escaped.
    pub fn h(&self, s: &str) -> String {
        safe::html(&self.red.text(s))
    }
    /// Returns the string for Markdown: masked and escaped.
    pub fn m(&self, s: &str) -> String {
        safe::md(&self.red.text(s))
    }
    /// Caveat about included findings on hosts outside the scope (tagged by the engine; they
    /// are excluded from the risk score), or `None` when there are none.
    pub fn oos_caveat(&self) -> Option<String> {
        let n = self
            .main
            .iter()
            .filter(|f| {
                f.tags
                    .iter()
                    .any(|t| t == foca_analysis::findings::OUT_OF_SCOPE_TAG)
            })
            .count();
        (n > 0).then(|| self.t.oos_caveat.replace("{n}", &n.to_string()))
    }
    /// Report reference of a finding (`F-1`, `F-2`, … in the order the report lists them).
    pub fn fref(&self, f: &Finding) -> String {
        match self.num.get(&f.id) {
            Some(n) => format!("F-{n}"),
            None => format!("F-{}", f.id),
        }
    }
    pub fn sev(&self, s: foca_core::Severity) -> &'static str {
        i18n::sev(self.o.lang, s)
    }
    pub fn status(&self, s: foca_core::FindingStatus) -> &'static str {
        i18n::status(self.o.lang, s)
    }
    pub fn doc_name(&self, id: u64) -> String {
        self.doc_names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("#{id}"))
    }
    /// Labels a scan for the reader by its start date and time instead of the internal id
    /// (`r2-life-s2-mwpq5xhd` → `19.11.2026 21:00`, `2026-11-19 21:00` in English). Unknown ids
    /// are returned as is.
    pub fn scan_label(&self, id: &str) -> String {
        let Some(s) = self.snap.scans.iter().find(|s| s.id == id) else {
            return id.to_string();
        };
        let iso = s.started_at.as_str();
        let (Some(y), Some(mo), Some(d)) = (iso.get(0..4), iso.get(5..7), iso.get(8..10)) else {
            return id.to_string();
        };
        let hm = iso.get(11..16).map(|t| format!(" {t}")).unwrap_or_default();
        match self.o.lang {
            Lang::En => format!("{y}-{mo}-{d}{hm}"),
            _ => format!("{d}.{mo}.{y}{hm}"),
        }
    }
    /// Report date in the report language: `25.11.2026` (RU/UK), `25 Nov 2026` (EN).
    pub fn date(&self) -> String {
        if self.o.lang == Lang::En {
            const MONTHS: [&str; 12] = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            return format!(
                "{} {} {:04}",
                self.now.day(),
                MONTHS[u8::from(self.now.month()) as usize - 1],
                self.now.year()
            );
        }
        format!(
            "{:02}.{:02}.{:04}",
            self.now.day(),
            u8::from(self.now.month()),
            self.now.year()
        )
    }
    pub fn iso_date(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}",
            self.now.year(),
            u8::from(self.now.month()),
            self.now.day()
        )
    }
    /// Returns RFC 3339 time in the device zone (`…Z` only for UTC).
    pub fn iso_time(&self) -> String {
        self.now
            .replace_nanosecond(0)
            .unwrap_or(self.now)
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    }
    /// Formats a date-time in device local time (the log stores UTC with a zone).
    pub fn ts(&self, iso: &str) -> String {
        data::dmy_hm(&data::local_iso(iso, self.now.offset()))
    }
    /// Device time zone in which all report times are shown.
    pub fn tz(&self) -> String {
        data::tz_label(self.now.offset())
    }
    /// Template label in the report language.
    pub fn tpl_label(&self) -> &'static str {
        tpl_label(self.o.tpl, self.o.lang)
    }
    pub fn yes_no(&self, b: bool) -> &'static str {
        if b {
            self.t.yes
        } else {
            self.t.no
        }
    }
    pub fn secret_mode(&self) -> &'static str {
        self.t.secret_modes[match self.o.secrets {
            SecretMode::Hide => 0,
            SecretMode::Partial => 1,
            SecretMode::Full => 2,
        }]
    }
}

/// Returns the template label (`Report.tpl`).
pub fn tpl_label(t: Template, l: Lang) -> &'static str {
    match (t, l) {
        (Template::Full, Lang::Ru) => "Полный отчёт пентеста",
        (Template::Full, Lang::Uk) => "Повний звіт пентесту",
        (Template::Full, Lang::En) => "Full pentest report",
        (Template::Summary, Lang::Ru) => "Краткая сводка",
        (Template::Summary, Lang::Uk) => "Коротке зведення",
        (Template::Summary, Lang::En) => "Executive brief",
        (Template::Data, Lang::Ru) => "Данные",
        (Template::Data, Lang::Uk) => "Дані",
        (Template::Data, Lang::En) => "Data",
        (Template::Executive, Lang::Ru) => "Для руководства (1 страница)",
        (Template::Executive, Lang::Uk) => "Для керівництва (1 сторінка)",
        (Template::Executive, Lang::En) => "Executive (1 page)",
        (Template::Compliance, Lang::Ru) => "КСЗИ / Соответствие",
        (Template::Compliance, Lang::Uk) => "КСЗІ / Відповідність",
        (Template::Compliance, Lang::En) => "КСЗІ / Compliance",
        (Template::Lab, Lang::Ru) => "Лабораторная работа",
        (Template::Lab, Lang::Uk) => "Лабораторна робота",
        (Template::Lab, Lang::En) => "Laboratory work",
    }
}

/// Builds a report without a request log (the log section will be empty).
pub fn build_report(snap: &Snapshot, o: &ReportOptions, now: OffsetDateTime) -> ReportArtifact {
    build_report_with_log(snap, &[], o, now)
}

/// Builds a report including the outgoing request log.
pub fn build_report_with_log(
    snap: &Snapshot,
    log: &[RequestEntry],
    o: &ReportOptions,
    now: OffsetDateTime,
) -> ReportArtifact {
    build_report_with_visuals(snap, log, &Visuals::default(), o, now)
}

/// Builds a report with the request log and diagram data. HTML gets inline SVG sections
/// (link graph, internal network map, chronology, activity) for the parts that have data;
/// Markdown gets their text form; CSV/JSON ignore the diagrams.
pub fn build_report_with_visuals(
    snap: &Snapshot,
    log: &[RequestEntry],
    vis: &Visuals,
    o: &ReportOptions,
    now: OffsetDateTime,
) -> ReportArtifact {
    // Finding texts (written by the core in Russian) are localized; CSV/JSON keep the data as
    // is.
    let pii = sections::forensics::pii_meta(snap);
    // Evidence that only repeats the description (header checks) says nothing new: show
    // the checked URL instead.
    let repeats =
        |f: &Finding| !f.evidence.trim().is_empty() && f.evidence.trim() == f.description.trim();
    let deduped;
    let snap = if matches!(
        o.fmt,
        ReportFormat::Html | ReportFormat::Md | ReportFormat::Docx
    ) && snap.findings.iter().any(repeats)
    {
        let mut s = snap.clone();
        for f in s.findings.iter_mut().filter(|f| repeats(f)) {
            f.evidence = f.url.clone().unwrap_or_default();
        }
        deduped = s;
        &deduped
    } else {
        snap
    };
    let localized;
    let snap = if o.lang != Lang::Ru
        && matches!(
            o.fmt,
            ReportFormat::Html | ReportFormat::Md | ReportFormat::Docx
        ) {
        let mut s = snap.clone();
        for f in &mut s.findings {
            *f = ftext::localize(f, o.lang);
        }
        let l = o.lang;
        for x in &mut s.software {
            x.name = ftext::terms(&x.name, l);
        }
        for x in &mut s.emails {
            x.src = ftext::terms(&x.src, l);
        }
        for x in &mut s.scans {
            x.profile = ftext::terms(&x.profile, l);
            x.egress = ftext::terms(&x.egress, l);
        }
        localized = s;
        &localized
    } else {
        snap
    };
    // Several findings with one title (the same check in different documents) read as
    // duplicates: add the document (or host) to tell them apart.
    let titled;
    let snap = if matches!(
        o.fmt,
        ReportFormat::Html | ReportFormat::Md | ReportFormat::Docx
    ) {
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for f in &snap.findings {
            *seen.entry(f.title.as_str()).or_default() += 1;
        }
        let dups: std::collections::BTreeSet<String> = seen
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(t, _)| t.to_string())
            .collect();
        if dups.is_empty() {
            snap
        } else {
            let mut s = snap.clone();
            let names: BTreeMap<u64, String> = s
                .docs
                .iter()
                .map(|d| {
                    (
                        d.id,
                        if d.name.is_empty() {
                            d.url.clone()
                        } else {
                            d.name.clone()
                        },
                    )
                })
                .collect();
            for f in s.findings.iter_mut().filter(|f| dups.contains(&f.title)) {
                let what = f
                    .doc
                    .or_else(|| f.provenance.docs.first().copied())
                    .and_then(|d| names.get(&d).cloned())
                    .unwrap_or_else(|| f.host.clone());
                if !what.is_empty() && !f.title.contains(&what) {
                    f.title = format!("{} · {what}", f.title);
                }
            }
            titled = s;
            &titled
        }
    } else {
        snap
    };
    let sel = data::select(snap, o);
    let pages = data::pages_estimate(o, sel.main.len(), sel.fixed.len());
    let res = ResultSnapshot::build(snap, &sel, pages);
    let ov = data::overview(snap, o.lang);
    let ls = data::log_summary(log);
    let version = o.version.unwrap_or_else(|| next_version(snap));
    let file_name = report_file_name(snap, o, version);
    let doc_names = snap
        .docs
        .iter()
        .map(|d| {
            let n = if d.name.is_empty() { &d.url } else { &d.name };
            (d.id, n.clone())
        })
        .collect();
    let red = mask::Redactor::new(snap, o.secrets, o.lang);
    let vis = if matches!(
        o.fmt,
        ReportFormat::Html | ReportFormat::Md | ReportFormat::Docx
    ) {
        vis.map_text(&|s| red.text(s))
    } else {
        Visuals::default()
    };
    let num = sel
        .main
        .iter()
        .chain(sel.fixed.iter())
        .enumerate()
        .map(|(i, f)| (f.id, i + 1))
        .collect();
    let ctx = Ctx {
        snap,
        log,
        o,
        t: i18n::strings(o.lang),
        main: sel.main,
        fixed: sel.fixed,
        res,
        ov,
        ls,
        red,
        now,
        doc_names,
        vis,
        pii,
        num,
    };
    let bytes = match o.fmt {
        ReportFormat::Html if o.tpl.is_standalone() => templates::render_html(&ctx).into_bytes(),
        ReportFormat::Md if o.tpl.is_standalone() => templates::render_md(&ctx).into_bytes(),
        ReportFormat::Html => formats::html::render(&ctx).into_bytes(),
        ReportFormat::Md => formats::md::render(&ctx).into_bytes(),
        ReportFormat::Csv => formats::tabular::report_csv(&ctx),
        ReportFormat::Json => formats::tabular::report_json(&ctx).into_bytes(),
        ReportFormat::Docx => formats::docx::render(&ctx),
    };
    let summary = ReportSummary {
        counts: ctx.res.counts,
        total: ctx.res.total,
        fixed: ctx.res.fixed_ids.len() as u32,
        risk: ctx.res.risk,
        risk_level: ctx.res.risk_level.clone(),
        project_risk: ctx.res.project_risk,
        pages,
        docs: ctx.ov.docs_total,
        people: ctx.ov.people,
        emails: ctx.ov.emails,
        hosts: ctx.ov.hosts,
        software: ctx.ov.software,
        eol_software: ctx.ov.eol_software.len() as u32,
        secrets: ctx.ov.secrets,
        requests: ctx.ls.total,
    };
    let lang = if matches!(o.fmt, ReportFormat::Csv | ReportFormat::Json) {
        "-".to_string()
    } else {
        o.lang.ui().to_string()
    };
    ReportArtifact {
        bytes,
        file_name,
        mime: o.fmt.mime(),
        version,
        lang,
        summary,
        results_snapshot: ctx.res.clone(),
        opts: normalized_opts(o),
    }
}

/// Returns the options in the `report_build.opts` shape (the logo is reduced to a flag,
/// without the image).
pub fn normalized_opts(o: &ReportOptions) -> Value {
    json!({
        "tpl": tpl_label(o.tpl, o.lang),
        "tpl_id": match o.tpl { Template::Summary => "brief", t => t.id() },
        "fmt": o.fmt.ext(),
        "lang": o.lang.ui(),
        "min_sev": o.min_sev.map(data::sev_id).unwrap_or("all"),
        "confirmed": o.confirmed,
        "sections": o.sections,
        "picked": o.picked,
        "picked_only": o.picked_only,
        "secrets": o.secrets.id(),
        "company": o.company,
        "logo": !matches!(o.logo, Logo::None),
    })
}

/// `report_templates`: `[{ id, title, description }]` in the UI language (`full` first).
pub fn report_templates(lang: Lang) -> Value {
    Value::Array(
        i18n::template_catalog(lang)
            .iter()
            .map(|(id, title, description)| json!({ "id": id, "title": title, "description": description }))
            .collect(),
    )
}
