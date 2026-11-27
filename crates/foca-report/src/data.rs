//! Report data: finding selection (like `FOCA_RULES.reportSelect`), risk over the selected
//! findings, the result snapshot for history, the summary and the request log.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::{Finding, Snapshot};
use foca_core::{FindingStatus, Severity};
use serde::{Deserialize, Serialize};

use crate::opts::ReportOptions;

/// An outgoing request log entry (the shape of `foca_store::RequestLog` plus a blocked
/// flag).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RequestEntry {
    pub time: String,
    pub scan_id: Option<String>,
    pub module: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub status: Option<u16>,
    pub bytes: u64,
    /// Request to the target (active phase) rather than to a third-party service.
    pub active: bool,
    /// Blocked by the scope policy (no network call was made).
    pub blocked: bool,
    pub error: Option<String>,
    /// Module note (brute force: `soft404` | `calibration` | `filtered` | `rate_limited`).
    pub note: Option<String>,
    /// Response content type.
    pub ctype: Option<String>,
}

impl RequestEntry {
    /// Returns `true` if the log error means the request was blocked by the scope (`code` or
    /// `code: detail`; `active_not_allowed` comes from 0.2.x logs).
    pub fn is_blocked_code(err: Option<&str>) -> bool {
        foca_core::scope::is_scope_block(err)
    }
}

pub const SEV_ORDER: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

pub fn sev_id(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "crit",
        Severity::High => "high",
        Severity::Medium => "warn",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

pub fn status_id(s: FindingStatus) -> &'static str {
    match s {
        FindingStatus::New => "new",
        FindingStatus::Confirmed => "confirmed",
        FindingStatus::FalsePositive => "false",
        FindingStatus::Accepted => "accepted",
        FindingStatus::Fixed => "fixed",
    }
}

/// Returns `true` for an active finding: neither a false positive nor fixed.
pub fn is_live(f: &Finding) -> bool {
    !matches!(
        f.status,
        FindingStatus::FalsePositive | FindingStatus::Fixed
    )
}

/// Report selection ordered by severity: `main` holds active findings matching the filters,
/// `fixed` the fixed ones.
pub struct Selection<'a> {
    pub main: Vec<&'a Finding>,
    pub fixed: Vec<&'a Finding>,
}

pub fn select<'a>(snap: &'a Snapshot, o: &ReportOptions) -> Selection<'a> {
    let pass = |f: &Finding| {
        o.min_sev.is_none_or(|m| f.sev.rank() >= m.rank())
            && (!o.picked_only || o.picked.contains(&f.id))
    };
    let by_sev = |a: &&Finding, b: &&Finding| b.sev.rank().cmp(&a.sev.rank()).then(a.id.cmp(&b.id));
    let mut main: Vec<&Finding> = snap
        .findings
        .iter()
        .filter(|f| is_live(f) && (!o.confirmed || f.status == FindingStatus::Confirmed) && pass(f))
        .collect();
    main.sort_by(by_sev);
    let mut fixed: Vec<&Finding> = if o.sections.fixed {
        snap.findings
            .iter()
            .filter(|f| f.status == FindingStatus::Fixed && pass(f))
            .collect()
    } else {
        Vec::new()
    };
    fixed.sort_by(by_sev);
    Selection { main, fixed }
}

/// Counts per severity (`crit…info`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub crit: u32,
    pub high: u32,
    pub warn: u32,
    pub low: u32,
    pub info: u32,
}

impl Counts {
    pub fn of<'a>(list: impl IntoIterator<Item = &'a Finding>) -> Counts {
        let mut c = Counts::default();
        for f in list {
            *c.get_mut(f.sev) += 1;
        }
        c
    }
    pub fn get(&self, s: Severity) -> u32 {
        match s {
            Severity::Critical => self.crit,
            Severity::High => self.high,
            Severity::Medium => self.warn,
            Severity::Low => self.low,
            Severity::Info => self.info,
        }
    }
    fn get_mut(&mut self, s: Severity) -> &mut u32 {
        match s {
            Severity::Critical => &mut self.crit,
            Severity::High => &mut self.high,
            Severity::Medium => &mut self.warn,
            Severity::Low => &mut self.low,
            Severity::Info => &mut self.info,
        }
    }
}

/// Returns `true` if there is data to assess risk: a finished scan or analyzed documents
/// (local analysis).
pub fn has_data(snap: &Snapshot) -> bool {
    snap.scans.iter().any(|s| s.status == "done")
        || snap.docs.iter().any(|d| d.status == "analyzed")
}

/// Computes risk `100·(1 − Π(1 − wᵢ))` over the given findings (same formula as
/// `foca_analysis::risk`).
pub fn risk_of(list: &[&Finding], has_data: bool) -> Option<u8> {
    let owned: Vec<Finding> = list.iter().map(|f| (*f).clone()).collect();
    foca_analysis::findings::risk(&owned, has_data).score
}

/// Returns `true` if a critical finding counts towards the risk score: live (neither a false
/// positive nor fixed) and not tagged out of scope: the same filter as
/// `foca_analysis::findings::risk`, so the level never comes from a finding the score ignores.
pub fn has_scored_critical(list: &[&Finding]) -> bool {
    list.iter().any(|f| {
        f.sev == Severity::Critical
            && is_live(f)
            && !f
                .tags
                .iter()
                .any(|t| t == foca_analysis::findings::OUT_OF_SCOPE_TAG)
    })
}

/// Maps a score to the UI risk level: `crit` ≥ 90 with critical findings, `high` ≥ 70,
/// `mid` ≥ 40, `low`, or `none` without data (same scale as `FOCA_RULES.riskLevel` in
/// ui/js/sel.js).
pub fn risk_level(score: Option<u8>, has_crit: bool) -> &'static str {
    match score {
        None => "none",
        Some(s) if s >= 90 && has_crit => "crit",
        Some(s) if s >= 70 => "high",
        Some(s) if s >= 40 => "mid",
        Some(_) => "low",
    }
}

/// A short copy of a finding in the snapshot, so history can show it even if the finding
/// changes later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingBrief {
    pub id: u64,
    pub title: String,
    pub sev: Severity,
    pub status: FindingStatus,
    pub host: String,
}

/// Result snapshot at build time (`Report.result` in the UI: `finding_ids`, `fixed_ids`,
/// `counts`, `total`, `risk`, `risk_level`, `pages`, `project_risk`, `at_scan`) plus short
/// copies of the findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultSnapshot {
    pub finding_ids: Vec<u64>,
    pub fixed_ids: Vec<u64>,
    pub counts: Counts,
    pub total: u32,
    pub risk: Option<u8>,
    pub risk_level: String,
    pub pages: Option<u32>,
    pub project_risk: Option<u8>,
    pub at_scan: Option<String>,
    pub findings: Vec<FindingBrief>,
    pub fixed: Vec<FindingBrief>,
}

fn brief(f: &Finding) -> FindingBrief {
    FindingBrief {
        id: f.id,
        title: f.title.clone(),
        sev: f.sev,
        status: f.status,
        host: f.host.clone(),
    }
}

impl ResultSnapshot {
    pub fn build(snap: &Snapshot, sel: &Selection, pages: Option<u32>) -> ResultSnapshot {
        let hd = has_data(snap);
        let risk = risk_of(&sel.main, hd);
        let all: Vec<&Finding> = snap.findings.iter().collect();
        ResultSnapshot {
            finding_ids: sel.main.iter().map(|f| f.id).collect(),
            fixed_ids: sel.fixed.iter().map(|f| f.id).collect(),
            counts: Counts::of(sel.main.iter().copied()),
            total: sel.main.len() as u32,
            risk,
            risk_level: risk_level(risk, has_scored_critical(&sel.main)).into(),
            pages,
            project_risk: risk_of(&all, hd),
            at_scan: snap.scans.last().map(|s| s.id.clone()),
            findings: sel.main.iter().map(|f| brief(f)).collect(),
            fixed: sel.fixed.iter().map(|f| brief(f)).collect(),
        }
    }
}

/// Estimates the number of A4 pages (same formula as the UI and the demo backend). The short
/// summary lists findings as table rows (about 25 per page), not as cards.
pub fn pages_estimate(o: &ReportOptions, main: usize, fixed: usize) -> Option<u32> {
    use crate::opts::{ReportFormat, Template};
    if matches!(o.fmt, ReportFormat::Csv | ReportFormat::Json) {
        return None;
    }
    let s = &o.sections;
    let b = |on: bool, n: f64| if on { n } else { 0.0 };
    if o.tpl == Template::Summary {
        let raw = 1.0
            + b(s.summary, 0.5)
            + b(s.scope, 0.5)
            + b(s.findings, main as f64 * 0.04)
            + b(s.fixed, fixed as f64 * 0.03)
            + b(s.people, 2.0)
            + b(s.infra, 2.0)
            + b(s.docs, 3.0)
            + b(s.log, 6.0)
            + b(s.appx, 2.0);
        return Some((raw.round() as u32).max(1));
    }
    let raw = 3.0
        + b(s.summary, 2.0)
        + b(s.scope, 2.0)
        + b(s.findings, main as f64 * 1.6)
        + b(s.fixed, fixed as f64 * 0.5)
        + b(s.people, 4.0)
        + b(s.infra, 5.0)
        + b(s.docs, 6.0)
        + b(s.log, 12.0)
        + b(s.appx, 4.0);
    Some((raw.round() as u32).max(2))
}

#[cfg(test)]
mod pages_tests {
    use super::pages_estimate;
    use crate::opts::{ReportOptions, Sections, Template};

    #[test]
    fn short_summary_counts_table_rows_not_cards() {
        let mut o = ReportOptions {
            tpl: Template::Summary,
            sections: Sections::for_template(Template::Summary),
            ..Default::default()
        };
        assert_eq!(pages_estimate(&o, 10, 2), Some(2));
        assert_eq!(pages_estimate(&o, 0, 0), Some(2));
        assert!(pages_estimate(&o, 60, 0).unwrap() <= 5);
        o.tpl = Template::Full;
        o.sections = Sections::for_template(Template::Full);
        assert!(pages_estimate(&o, 10, 2).unwrap() > 20);
    }
}

/// Project summary.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Overview {
    /// Documents (excluding deleted ones) by extension, descending.
    pub docs_by_type: Vec<(String, u32)>,
    pub docs_total: u32,
    pub docs_analyzed: u32,
    /// Top 10 people as (login, name, documents).
    pub top_people: Vec<(String, String, u32)>,
    /// Top 10 software as (name and version, documents).
    pub top_software: Vec<(String, u32)>,
    /// Top 10 software seen on hosts (CPE/banners of `Host.tech`, website technologies with
    /// a version) as (name and version, hosts).
    pub host_software: Vec<(String, u32)>,
    /// All outdated software as (name and version, EOL date or reason, CVE count; `None` if
    /// not checked). Includes outdated website technologies.
    pub eol_software: Vec<(String, String, Option<u32>)>,
    /// Known CVEs per product (offline NVD table): product, where, version, CVE count, severity
    /// bands with KEV, max CVSS with EPSS, last document, top CVEs (plain text cells).
    pub cve_products: Vec<Vec<String>>,
    pub people: u32,
    pub emails: u32,
    pub hosts: u32,
    pub hosts_internal: u32,
    pub pcs: u32,
    pub servers: u32,
    pub printers: u32,
    pub paths: u32,
    pub software: u32,
    pub secrets: u32,
}

/// Returns the software label for the report: full name plus normalized version, e.g.
/// `Microsoft Office Word 2007 (12)`. Applications without a version (office, PDF, graphics)
/// get a localized "version unknown" suffix. The internal key (`word2007`) never reaches the
/// report.
pub fn sw_label(s: &foca_core::api::Software, lang: crate::Lang) -> String {
    let name = crate::ftext::terms(&s.name, lang);
    let ver = s.ver.trim();
    if ver.is_empty() {
        if matches!(s.kind.as_str(), "office" | "pdf" | "image" | "")
            && !name.chars().any(|c| c.is_ascii_digit())
        {
            let unk = match lang {
                crate::Lang::Ru => "версия неизвестна",
                crate::Lang::Uk => "версія невідома",
                crate::Lang::En => "version unknown",
            };
            return format!("{name} ({unk})");
        }
        return name;
    }
    if name.contains(ver) {
        name
    } else {
        format!("{name} ({ver})")
    }
}

/// Returns the software label by key (`Doc.software` holds a `Software` id); unknown keys
/// are returned as is.
pub fn sw_label_by_id(snap: &Snapshot, id: &str, lang: crate::Lang) -> String {
    snap.software
        .iter()
        .find(|s| s.id == id)
        .map(|s| sw_label(s, lang))
        .unwrap_or_else(|| id.to_string())
}

/// Returns the CVE count; `None` means no data (not checked), not "0 vulnerabilities".
/// Rows of the "known CVEs per product" table: document software with a CVE summary and site
/// technologies; products without a version show the known count only. Most matched first.
fn cve_products(
    snap: &Snapshot,
    recon: &crate::recon_view::ReconView,
    lang: crate::Lang,
) -> Vec<Vec<String>> {
    let t = crate::i18n::strings(lang);
    let mut rows: Vec<(u32, Vec<String>)> = Vec::new();
    let mut push =
        |label: String, side: &str, last: Option<&str>, c: &foca_core::api::CveSummary| {
            if (c.version_known && c.matched == 0) || (!c.version_known && c.known == 0) {
                return;
            }
            let side = match side {
                "server" => t.side_server,
                "workstation" => t.side_workstation,
                _ => t.side_site,
            };
            let num = |x: Option<f32>| x.map_or_else(|| "-".to_string(), |v| format!("{v}"));
            let (count, bands, cvss, top) = if c.version_known {
                let mut bands = format!("{}/{}/{}/{}", c.critical, c.high, c.medium, c.low);
                if c.kev > 0 {
                    bands.push_str(&format!(" · KEV {}", c.kev));
                }
                let mut cvss = num(c.max_cvss);
                if let Some(e) = c.max_epss {
                    cvss.push_str(&format!(" · EPSS {e:.2}"));
                }
                // top 10 (KEV, CVSS, EPSS order) with the total when the list is longer
                let top: Vec<&str> = c.cves.iter().take(10).map(|r| r.id.as_str()).collect();
                let mut top = top.join(", ");
                if c.matched as usize > 10 {
                    top.push_str(&format!(" (10/{})", c.matched));
                }
                (c.matched.to_string(), bands, cvss, top)
            } else {
                (
                    format!("{} ({})", c.known, t.version_unknown),
                    "-".into(),
                    "-".into(),
                    "-".into(),
                )
            };
            let version = if c.version.is_empty() {
                "-".to_string()
            } else {
                c.version.clone()
            };
            rows.push((
                if c.version_known { c.matched } else { 0 },
                vec![
                    label,
                    side.to_string(),
                    version,
                    count,
                    bands,
                    cvss,
                    last.map_or_else(|| "-".to_string(), dmy),
                    top,
                ],
            ));
        };
    for s in &snap.software {
        if let Some(c) = &s.cve_sum {
            push(sw_label(s, lang), &s.side, s.last_doc.as_deref(), c);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for x in &recon.tech {
        if let Some(c) = &x.cve {
            let label = tech_label(&x.name, x.version.as_deref());
            if seen.insert(label.to_ascii_lowercase()) {
                push(label, "site", None, c);
            }
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(a.1[0].cmp(&b.1[0])));
    rows.into_iter().map(|r| r.1).collect()
}

pub fn sw_cve(s: &foca_core::api::Software) -> Option<u32> {
    if s.cve == 0 && s.cves.is_empty() {
        None
    } else {
        Some(s.cve)
    }
}

/// Formats an EOL date for tables as `DD.MM.YYYY`; software out of support without a
/// published date gets a localized "date unknown".
pub fn eol_label(date: &str, lang: crate::Lang) -> String {
    if date.trim().is_empty() {
        match lang {
            crate::Lang::Ru => "дата неизвестна",
            crate::Lang::Uk => "дата невідома",
            crate::Lang::En => "date unknown",
        }
        .into()
    } else {
        dmy(date)
    }
}

/// Returns the product family used to group top software: the name without trailing tokens
/// containing digits (`Microsoft Office Word 2007` → `Microsoft Office Word`).
fn sw_family(name: &str) -> String {
    let mut w: Vec<&str> = name.split_whitespace().collect();
    while w.len() > 1
        && w.last()
            .is_some_and(|t| t.chars().any(|c| c.is_ascii_digit()))
    {
        w.pop();
    }
    w.join(" ").to_lowercase()
}

pub fn overview(snap: &Snapshot, lang: crate::Lang) -> Overview {
    let live: Vec<_> = snap.docs.iter().filter(|d| !d.deleted).collect();
    let mut by_type: BTreeMap<String, u32> = BTreeMap::new();
    for d in &live {
        let e = if d.ext.is_empty() {
            "?".to_string()
        } else {
            d.ext.to_lowercase()
        };
        *by_type.entry(e).or_default() += 1;
    }
    let mut docs_by_type: Vec<(String, u32)> = by_type.into_iter().collect();
    docs_by_type.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut people: Vec<_> = snap.people.iter().filter(|p| !p.service).collect();
    people.sort_by(|a, b| b.docs.cmp(&a.docs).then(a.login.cmp(&b.login)));
    let mut sw: Vec<_> = snap.software.iter().collect();
    sw.sort_by(|a, b| b.docs.cmp(&a.docs).then(a.id.cmp(&b.id)));
    // Top software: versions of one product stay together; families are ranked by total
    // documents.
    let mut fam: BTreeMap<String, u32> = BTreeMap::new();
    for s in &sw {
        *fam.entry(sw_family(&s.name)).or_default() += s.docs;
    }
    let mut top = sw.clone();
    top.sort_by(|a, b| {
        let (fa, fb) = (sw_family(&a.name), sw_family(&b.name));
        fam[&fb]
            .cmp(&fam[&fa])
            .then(fa.cmp(&fb))
            .then(b.docs.cmp(&a.docs))
            .then(a.id.cmp(&b.id))
    });
    let recon = crate::recon_view::ReconView::from_snapshot(&snap.recon);
    let host_sw = host_software(snap, &recon);
    let mut eol_software: Vec<(String, String, Option<u32>)> = sw
        .iter()
        .filter(|s| s.eol)
        .map(|s| {
            (
                sw_label(s, lang),
                s.eol_date.clone().unwrap_or_default(),
                sw_cve(s),
            )
        })
        .collect();
    for x in recon.tech.iter().filter(|x| x.outdated.is_some()) {
        let label = tech_label(&x.name, x.version.as_deref());
        if !eol_software
            .iter()
            .any(|e| e.0.eq_ignore_ascii_case(&label))
        {
            let why = crate::ftext::outdated_note(x.outdated.as_deref().unwrap_or(""), lang);
            eol_software.push((label, why, None));
        }
    }
    let cve_products = cve_products(snap, &recon, lang);
    Overview {
        cve_products,
        docs_total: live.len() as u32,
        docs_analyzed: live.iter().filter(|d| d.status == "analyzed").count() as u32,
        docs_by_type,
        top_people: people
            .iter()
            .take(10)
            .map(|p| (p.login.clone(), p.name.clone(), p.docs))
            .collect(),
        top_software: top
            .iter()
            .take(10)
            .map(|s| (sw_label(s, lang), s.docs))
            .collect(),
        host_software: host_sw.iter().take(10).cloned().collect(),
        eol_software,
        people: snap.people.len() as u32,
        emails: snap.emails.len() as u32,
        // storage providers (Google Drive, S3, ...) hold files, they are not the target's hosts
        hosts: snap
            .hosts
            .iter()
            .filter(|h| !foca_analysis::util::is_storage_provider(&h.name))
            .count() as u32,
        hosts_internal: snap.hosts.iter().filter(|h| h.internal).count() as u32,
        pcs: snap.pcs.len() as u32,
        servers: snap.pcs.iter().filter(|p| p.kind == "server").count() as u32,
        printers: snap.printers.len() as u32,
        paths: snap.paths.len() as u32,
        software: (snap.software.len() + host_sw.len()) as u32,
        secrets: snap.secrets.len() as u32,
    }
}

fn tech_label(name: &str, ver: Option<&str>) -> String {
    match ver.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) if !name.contains(v) => format!("{name} {v}"),
        _ => name.to_string(),
    }
}

/// Software seen on hosts: versioned technologies of `Host.tech` (CPE / banners, `Apache HTTP Server
/// 2.4.58, PHP 8.1.2`) and website technologies with a known version, as (label, number of
/// hosts), most widespread first.
fn host_software(snap: &Snapshot, recon: &crate::recon_view::ReconView) -> Vec<(String, u32)> {
    let mut by: BTreeMap<String, (String, std::collections::BTreeSet<String>)> = BTreeMap::new();
    let mut add = |label: String, host: &str| {
        let label = label.trim().to_string();
        if label.is_empty() || label == "-" {
            return;
        }
        by.entry(label.to_lowercase())
            .or_insert_with(|| (label, Default::default()))
            .1
            .insert(host.to_string());
    };
    for h in &snap.hosts {
        // Only versioned products: labels like `RDP` or `Citrix ICA` describe a service,
        // not installed software.
        for t in h
            .tech
            .split(", ")
            .filter(|t| t.chars().any(|c| c.is_ascii_digit()))
        {
            add(t.to_string(), &h.name);
        }
    }
    for x in recon.tech.iter().filter(|x| x.version.is_some()) {
        add(tech_label(&x.name, x.version.as_deref()), &x.host);
    }
    let mut out: Vec<(String, u32)> = by
        .into_values()
        .map(|(l, hs)| (l, hs.len() as u32))
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

/// Request log summary.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LogSummary {
    pub total: u32,
    pub passive: u32,
    pub active: u32,
    pub blocked: u32,
    pub errors: u32,
    pub by_module: Vec<(String, u32)>,
    pub hosts: u32,
    /// Target hosts (active requests) and third-party services (passive) are counted
    /// separately.
    pub hosts_target: u32,
    pub hosts_third: u32,
    pub first: Option<String>,
    pub last: Option<String>,
}

pub fn log_summary(log: &[RequestEntry]) -> LogSummary {
    let mut by: BTreeMap<String, u32> = BTreeMap::new();
    let mut hosts = BTreeSet::new();
    let (mut tgt, mut third) = (BTreeSet::new(), BTreeSet::new());
    let mut s = LogSummary::default();
    for r in log {
        s.total += 1;
        if r.blocked {
            s.blocked += 1;
        } else if r.active {
            s.active += 1;
        } else {
            s.passive += 1;
        }
        if r.error.is_some() && !r.blocked {
            s.errors += 1;
        }
        *by.entry(r.module.clone()).or_default() += 1;
        if !r.host.is_empty() {
            hosts.insert(r.host.clone());
            if r.active || r.blocked {
                tgt.insert(r.host.clone());
            } else {
                third.insert(r.host.clone());
            }
        }
    }
    let mut times: Vec<&str> = log
        .iter()
        .map(|r| r.time.as_str())
        .filter(|t| !t.is_empty())
        .collect();
    times.sort_unstable();
    s.first = times.first().map(|t| t.to_string());
    s.last = times.last().map(|t| t.to_string());
    s.hosts = hosts.len() as u32;
    s.hosts_target = tgt.len() as u32;
    s.hosts_third = third.len() as u32;
    let mut bm: Vec<(String, u32)> = by.into_iter().collect();
    bm.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    s.by_module = bm;
    s
}

/// Converts `YYYY-MM-DD` to `DD.MM.YYYY` (anything else is returned as is).
pub fn dmy(iso: &str) -> String {
    let d = iso.get(..10).unwrap_or(iso);
    let p: Vec<&str> = d.split('-').collect();
    if p.len() == 3 && p[0].len() == 4 {
        format!("{}.{}.{}", p[2], p[1], p[0])
    } else {
        iso.to_string()
    }
}

/// Converts a log time with a zone (`2026-11-21T09:27:00Z`, RFC 3339) to device local time
/// `YYYY-MM-DDTHH:MM:SS`, like the other core dates. Strings without a zone are returned as
/// is.
pub fn local_iso(iso: &str, off: time::UtcOffset) -> String {
    use time::format_description::well_known::Rfc3339;
    match time::OffsetDateTime::parse(iso.trim(), &Rfc3339) {
        Ok(t) => {
            let t = t.to_offset(off);
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            )
        }
        Err(_) => iso.to_string(),
    }
}

/// Formats a time zone label: `UTC`, `UTC+2`, `UTC+5:30`, `UTC-3`.
pub fn tz_label(off: time::UtcOffset) -> String {
    let s = off.whole_seconds();
    if s == 0 {
        return "UTC".into();
    }
    let (sign, a) = if s < 0 { ('-', -s) } else { ('+', s) };
    let (h, m) = (a / 3600, a % 3600 / 60);
    if m == 0 {
        format!("UTC{sign}{h}")
    } else {
        format!("UTC{sign}{h}:{m:02}")
    }
}

pub fn dmy_hm(iso: &str) -> String {
    let date = dmy(iso);
    match iso.get(11..16) {
        Some(t) if iso.len() >= 16 => format!("{date} {t}"),
        _ => date,
    }
}
