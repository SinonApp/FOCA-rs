//! Project snapshot DTOs in exactly the format of `docs/API.md` (what the UI reads into `F.db`).
//!
//! The core model ([`crate::model`]) and the UI format differ (timestamps without an offset,
//! references by id, `host: "-"`, notes as objects), so the contract has its own types. They are
//! built by `foca-analysis` (entities and findings) and `foca-store` (project, scope, scans,
//! reports).
//!
//! Fields outside the contract are allowed only as additions (the UI ignores them) and are
//! called out in the type documentation.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::FindingStatus;
use crate::scope::Scope;
use crate::severity::Severity;
use crate::target::Target;

/// A secret value. It serializes verbatim (the UI snapshot masks it itself), but `Debug` and
/// `Display` print only the mask so the secret never leaks into logs or panic messages.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(v: impl Into<String>) -> Self {
        SecretValue(v.into())
    }
    /// Returns the plain value; use only for persistence and explicit display to the user.
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// Returns the mask: `ab…yz` for long values, `••••` for short ones.
    pub fn masked(&self) -> String {
        mask(&self.0)
    }
}

/// Masks a secret: keeps the first and last two characters of strings longer than 8, otherwise returns `••••`.
pub fn mask(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.len() > 8 {
        let head: String = chars[..2].iter().collect();
        let tail: String = chars[chars.len() - 2..].iter().collect();
        format!("{head}…{tail}")
    } else {
        "••••".to_string()
    }
}

/// Escapes a secret payload before wrapping in `{{s:...}}` so `}}` inside the secret
/// cannot terminate the marker early and leak trailing characters.
pub fn escape_secret_marker(v: &str) -> String {
    if !v.contains('}') {
        return v.to_string();
    }
    let mut out = String::with_capacity(v.len() + 8);
    let mut chars = v.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut k = 1usize;
            while chars.peek() == Some(&'\\') {
                chars.next();
                k += 1;
            }
            if chars.peek() == Some(&'}') {
                chars.next();
                for _ in 0..(2 * k + 1) {
                    out.push('\\');
                }
                out.push('}');
            } else {
                for _ in 0..k {
                    out.push('\\');
                }
            }
        } else if c == '}' {
            out.push_str("\\}");
        } else {
            out.push(c);
        }
    }
    out
}

/// Reverses [`escape_secret_marker`].
pub fn unescape_secret_marker(escaped: &str) -> String {
    if !escaped.contains('\\') {
        return escaped.to_string();
    }
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut m = 1usize;
            while chars.peek() == Some(&'\\') {
                chars.next();
                m += 1;
            }
            if chars.peek() == Some(&'}') {
                chars.next();
                for _ in 0..(m / 2) {
                    out.push('\\');
                }
                out.push('}');
            } else {
                for _ in 0..m {
                    out.push('\\');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Finds the byte index of the unescaped closing `}}` in the slice immediately following `{{s:`.
pub fn find_secret_marker_end(after: &str) -> Option<usize> {
    let bytes = after.as_bytes();
    let mut i = 0usize;
    let mut backslashes = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => backslashes += 1,
            b'}' => {
                if backslashes % 2 == 1 {
                    backslashes = 0;
                } else if bytes.get(i + 1) == Some(&b'}') {
                    return Some(i);
                } else {
                    backslashes = 0;
                }
            }
            _ => backslashes = 0,
        }
        i += 1;
    }
    None
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue({})", self.masked())
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.masked())
    }
}

/// `ProjectSummary`: an item of `project_list`.
///
/// The store caches it as JSON in the project index, so rows written by an older version lack
/// newer fields: `#[serde(default)]` keeps them readable after an upgrade.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectSummary {
    pub id: String,
    pub name: String,
    pub client: String,
    pub created_at: String,
    pub archived: bool,
    pub last_scan_at: Option<String>,
    pub last_profile: Option<String>,
    pub scans: u32,
    pub docs: u32,
    pub findings: u32,
    pub risk: Option<u8>,
    pub scanning: bool,
    pub progress: u8,
    /// Built-in reference case (`demo_case_import`): kept out of recent projects and never
    /// restored as the last opened project.
    pub reference: bool,
}

/// `Project`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectInfo {
    pub id: String,
    pub name: String,
    pub client: String,
    pub domain: String,
    pub created_at: String,
    pub archived: bool,
    pub notes: String,
}

/// A scope target in UI form. All network targets are checked by the active modules of the
/// full scan profile; the legacy `active` field from 0.2.x is ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScopeTarget {
    pub v: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// `Scope` in UI form: client, contact, note (`basis`), targets and exclusions.
/// Legacy 0.2.x fields (`num`, `from`, `to`, `forbid`, `allow_active`) are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScopeDto {
    pub client: String,
    pub contact: String,
    pub phone: String,
    pub basis: String,
    pub targets: Vec<ScopeTarget>,
    pub excl: Vec<String>,
}

/// The checkable scope of a UI scope: targets and exclusions that do not parse are dropped.
impl From<&ScopeDto> for Scope {
    fn from(s: &ScopeDto) -> Scope {
        Scope {
            targets: s
                .targets
                .iter()
                .filter_map(|t| Target::parse(&t.v).ok())
                .collect(),
            excludes: s
                .excl
                .iter()
                .filter_map(|t| Target::parse(t).ok())
                .collect(),
            active_phase: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocGps {
    pub lat: f64,
    pub lon: f64,
    pub place: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocRevision {
    /// `del` | `ins` | `com`
    pub kind: String,
    pub who: Option<String>,
    pub at: Option<String>,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocRdp {
    pub full_address: String,
    pub username: String,
    pub gateway: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocLnk {
    pub machine: String,
    pub mac: String,
    pub volume_serial: String,
    pub target: String,
    pub target_dir: String,
}

/// `Doc`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Doc {
    pub id: u64,
    pub ext: String,
    pub name: String,
    pub url: String,
    pub host: String,
    pub title: String,
    /// Size in KiB.
    pub size: u64,
    pub first_scan: Option<String>,
    pub deleted: bool,
    /// `analyzed` | `downloaded` | `queued` | `error`
    pub status: String,
    pub author: Option<String>,
    pub last_modified_by: Option<String>,
    pub software: Option<String>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub folder: Option<String>,
    pub printer: Option<String>,
    pub company: Option<String>,
    pub camera: Option<String>,
    pub gps: Option<DocGps>,
    pub revisions: Vec<DocRevision>,
    pub rdp: Option<DocRdp>,
    pub lnk: Option<DocLnk>,
    pub flags: Vec<String>,
    pub thumb_diff: bool,
    /// HTTP status of a failed fetch (`error_kind == "http"`), only when one was received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Why the document ended in `error` (download, parsing or import failure), as recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    /// What failed for a document in `error`: `parse` (the stored file could not be parsed or
    /// imported), `download` (the fetch failed) or `http` (the server returned an HTTP error).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Where the document link came from (crawler page, another document, public storage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<DocProvenance>,
    /// People named in the document text (unique spellings).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub text_people: u32,
    /// Contacts and personal identifiers in the document text (phones, e-mails, identifiers).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub text_contacts: u32,
}

/// How a document was reached: the in-scope page that linked it, or the downloaded document it
/// was found in; files on public external storage carry the provider and the link as found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocProvenance {
    /// `page` (linked from a crawled page) | `doc` (a link inside another document).
    pub kind: String,
    /// Page URL, or the name of the document the link was found in.
    pub from: String,
    /// Id of that document (`kind == "doc"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_doc: Option<u64>,
    /// Storage provider of a linked external file: `gdrive` | `gdocs` | `onedrive` | `dropbox` | `sharepoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    /// The storage link as found (the download URL differs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// Exported by Google (Docs/Sheets/Slides): the metadata is Google's, not the author's.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub export: bool,
    /// Steps of "found in a document" from a crawled page or search result (0 for direct links).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub depth: u8,
}

fn is_zero(v: &u8) -> bool {
    *v == 0
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// `Person`. Extra fields outside the contract: `aliases`, `service`, `emails`, `dept`,
/// `dept_conf`, `title`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Person {
    pub login: String,
    pub name: String,
    pub role: String,
    pub pc: Option<String>,
    pub color: String,
    pub src: String,
    /// `meta` | `text`
    pub src_kind: String,
    pub docs: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_doc: Option<u64>,
    /// All spellings merged into this person.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Service account (Administrator, User, scan, ...).
    #[serde(default)]
    pub service: bool,
    #[serde(default)]
    pub emails: Vec<String>,
    /// Department recovered from the documents (org chart): the dictionary key
    /// (`finance`, `hr`, …) or the share name of an unknown department.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dept: Option<String>,
    /// Confidence of the department assignment, 0-95.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dept_conf: Option<u8>,
    /// Job title from a signing certificate, or the position / academic title written next to
    /// the name in document text (`доцент, к.ю.н.`, `CTO`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Department, faculty or unit written next to the name in document text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Phone numbers written next to the name, masked (`+38••••••••67`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phones: Vec<String>,
    /// Kinds of personal identifiers written next to the name (`rnokpp`, `birth_date`,
    /// `pl_pesel`, ...); values are never stored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<String>,
    /// Named in a signature block (`_____ /Петренко І.В./`, `(підпис)`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signatory: bool,
    /// Line of the first text mention in `src_doc` (1-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_line: Option<u32>,
}

/// A phone number found in document text (`phones` snapshot key). The value is masked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phone {
    /// Masked number (`+38••••••••67`).
    pub value: String,
    /// ISO country (`UA`, `US`, ...) or empty when only the shape is known.
    #[serde(default)]
    pub country: String,
    /// Documents that contain the number.
    pub docs: u32,
    /// First document.
    #[serde(default)]
    pub src_doc: Option<u64>,
    /// Person the number is written next to (login).
    #[serde(default)]
    pub login: Option<String>,
}

/// `Email`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Email {
    pub addr: String,
    pub login: Option<String>,
    pub name: Option<String>,
    pub found: bool,
    pub src: String,
    pub role: bool,
}

/// Address pattern: `p` is the pattern (`{f}.{last}`), `ex` an example, `conf` the confidence
/// in percent, `n` the number of supporting addresses. `domain` is an extra field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pattern {
    pub p: String,
    pub ex: String,
    pub conf: u8,
    pub n: u32,
    #[serde(default)]
    pub domain: String,
}

/// `Software`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Software {
    pub id: String,
    pub name: String,
    pub ver: String,
    /// `office` | `pdf` | `scanner` | `camera` | `image`
    pub kind: String,
    pub released: Option<i32>,
    pub eol_date: Option<String>,
    pub eol: bool,
    pub cve: u32,
    pub cves: Vec<(String, f32)>,
    pub dev: Option<String>,
    pub docs: u32,
    /// NVD CPE `vendor:product` keys of the product (offline CVE table).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpe: Vec<String>,
    /// `server` (generator that runs on the site's servers) or `workstation` (desktop software
    /// of the document authors); empty when unknown.
    #[serde(default)]
    pub side: String,
    /// Date of the newest document made with this version (`YYYY-MM-DD`).
    #[serde(default)]
    pub last_doc: Option<String>,
    /// Offline NVD CVE summary of this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_sum: Option<CveSummary>,
}

/// One CVE of a [`CveSummary`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CveRef {
    pub id: String,
    pub cvss: Option<f32>,
    pub kev: bool,
    pub epss: Option<f32>,
    /// NVD lists the product without any version limit (range not specified in NVD): the CVE
    /// is shown but does not raise the severity.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unbounded: bool,
}

/// Offline NVD CVE summary of one product version (`docs/API.md`, "CVE summary").
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CveSummary {
    /// Matched CPE keys (`vendor:product`, plugins `vendor:product@wordpress`), comma separated.
    pub product: String,
    /// Version used for matching (empty when not determined).
    pub version: String,
    pub version_known: bool,
    /// Where the version comes from: `header`, `html`, `js`, `plugin_path`, `readme`, `meta`.
    pub source: String,
    /// CVEs of the product in the table (any version).
    pub known: u32,
    /// CVEs whose affected ranges contain the version.
    pub matched: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub max_cvss: Option<f32>,
    /// Matched CVEs in CISA KEV.
    pub kev: u32,
    pub max_epss: Option<f32>,
    /// Matched CVEs: KEV first, then by CVSS and EPSS.
    pub cves: Vec<CveRef>,
    /// CVEs that contain the version but were published after the year it was last seen in a
    /// document (the machine may have been updated since): not counted above.
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub later: u32,
    /// Matched CVEs whose NVD entry has no version limit for the product (included in
    /// `matched`, not in the severity counts, `kev` or `max_cvss`).
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub unbounded: u32,
    /// Lowest version outside every matched range ("update to"), when computable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
    /// Software seen in documents: only CVEs published up to this year are counted (the full
    /// list, `cve_list`, takes the same limit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until_year: Option<u16>,
}

/// `Host`. Extra field: `scope`, one of `in_scope` | `excluded` | `out_of_scope`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub name: String,
    pub ip: String,
    pub role: String,
    pub tech: String,
    pub cloud: String,
    pub services: Vec<(String, String, String)>,
    pub source: String,
    pub internal: bool,
    pub sev: String,
    pub first_scan: Option<String>,
    #[serde(default)]
    pub scope: String,
}

/// `Pc`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pc {
    pub name: String,
    /// `ws` | `server`
    pub kind: String,
    pub users: Vec<String>,
    pub ip: Option<String>,
    pub source: String,
    pub docs: u32,
}

/// `Path`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathItem {
    pub path: String,
    pub docs: u32,
    pub user: Option<String>,
    pub host: Option<String>,
}

/// `Printer`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Printer {
    pub name: String,
    pub docs: u32,
    pub host: Option<String>,
}

/// `Secret`. Extra field: `rule`, the rule that matched the value.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Secret {
    pub id: u64,
    /// `conn` | `pass` | `api` | `host`
    #[serde(rename = "type")]
    pub kind: String,
    pub value: SecretValue,
    pub doc: u64,
    #[serde(rename = "where")]
    pub location: String,
    pub sev: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<u64>,
    #[serde(default)]
    pub rule: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub text: String,
    pub who: String,
    pub time: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Photo {
    pub name: String,
    pub time: String,
    pub from: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FindingRel {
    pub people: Vec<String>,
    pub pcs: Vec<String>,
    pub docs: Vec<u64>,
}

/// Finding provenance: the rule and the objects it matched.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FindingProvenance {
    pub rule: String,
    /// Document fields or locations that provided the evidence (`core.xml:dc:creator`, the body text, ...).
    pub fields: Vec<String>,
    pub docs: Vec<u64>,
}

/// `Finding`. Extra field: `provenance`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: u64,
    pub title: String,
    pub sev: Severity,
    pub status: FindingStatus,
    pub host: String,
    pub category: String,
    pub source: String,
    pub module: String,
    pub active: bool,
    pub time: String,
    pub first_scan: Option<String>,
    pub fixed_scan: Option<String>,
    pub tags: Vec<String>,
    pub cve: Vec<String>,
    pub cvss: Option<f32>,
    pub mitre: String,
    pub description: String,
    pub recommendation: String,
    pub evidence: String,
    pub request: String,
    pub url: Option<String>,
    pub doc: Option<u64>,
    pub notes: Vec<Note>,
    pub photos: Vec<Photo>,
    pub rel: FindingRel,
    #[serde(default)]
    pub provenance: FindingProvenance,
}

/// `Gps`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GpsPoint {
    pub doc: u64,
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub place: String,
    pub dev: String,
    pub taken_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: u64,
}

/// Timeline `Event`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub y: i32,
    /// Month, `"01"` to `"12"`.
    pub m: String,
    pub ic: String,
    pub k: String,
    pub t: String,
    pub s: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sev: Option<String>,
    #[serde(rename = "ref")]
    pub reference: EventRef,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSource {
    pub id: String,
    pub name: String,
    pub status: String,
}

/// Scan result snapshot used for diffing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanSnapshot {
    pub docs: Vec<u64>,
    pub people: Vec<String>,
    pub hosts: BTreeMap<String, String>,
    pub findings: BTreeMap<String, Severity>,
    /// Site technologies from reconnaissance: name to version (`""` if unknown).
    pub tech: BTreeMap<String, String>,
}

/// Execution environment & snapshot completeness flags recorded for a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanEnv {
    pub egress: String,
    pub proxy_used: bool,
    pub tcp_intercept: bool,
    pub dns_hijack: bool,
    pub tls_mitm: bool,
    pub incomplete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete_sources: Vec<String>,
    /// Why each incomplete source is incomplete (same order as `incomplete_sources`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete_reasons: Vec<IncompleteSource>,
}

/// Reason a source's data is incomplete: its final status (`error`, `timeout`, `blocked`,
/// `captcha`, `limit`, `skipped`, or `lost` for an `ok` source that lost requests) and the HTTP
/// code of its last failed request, if any.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IncompleteSource {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<u16>,
}

/// `Scan`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Scan {
    pub id: String,
    pub profile_id: String,
    pub profile: String,
    pub active: bool,
    pub trigger: String,
    pub status: String,
    pub reason: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub minutes: u32,
    pub targets: Vec<String>,
    pub egress: String,
    pub sources: Vec<ScanSource>,
    pub docs: u32,
    pub hosts: u32,
    pub people: u32,
    pub findings: u32,
    pub new_findings: u32,
    pub snapshot: ScanSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<ScanEnv>,
}

/// `Report`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    pub id: u64,
    pub name: String,
    pub tpl: String,
    pub fmt: String,
    pub lang: String,
    pub created_at: String,
    pub size: String,
    pub opts: Value,
    /// Result snapshot taken when the report was generated (`Report.result`); the report history
    /// shows it instead of current data. `null` for older records.
    pub result: Value,
}

/// `Snapshot`, returned by `project_snapshot`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub project: ProjectInfo,
    pub scope: ScopeDto,
    pub docs: Vec<Doc>,
    pub people: Vec<Person>,
    pub emails: Vec<Email>,
    /// Phone numbers from document text (masked).
    pub phones: Vec<Phone>,
    pub patterns: Vec<Pattern>,
    pub hosts: Vec<Host>,
    pub pcs: Vec<Pc>,
    pub software: Vec<Software>,
    pub paths: Vec<PathItem>,
    pub printers: Vec<Printer>,
    pub secrets: Vec<Secret>,
    pub findings: Vec<Finding>,
    pub gps: Vec<GpsPoint>,
    pub events: Vec<Event>,
    pub scans: Vec<Scan>,
    pub reports: Vec<Report>,
    pub leaks: BTreeMap<String, Value>,
    pub settings: Value,
    pub scan: Value,
    /// Site reconnaissance (`ReconView`, `docs/API.md`), filled in by the engine; feeds the "site and technologies" report section.
    #[serde(skip_serializing_if = "Value::is_null")]
    pub recon: Value,
    /// Host ports for reports (`[{ host, ip, ports, ports_scan }]`), filled in by the engine only in
    /// report snapshots; the UI receives ports through `Host.ports` / `Host.ports_scan`.
    #[serde(skip_serializing_if = "Value::is_null")]
    pub ports: Value,
    /// Infrastructure records of the infrastructure modules for reports (`{ kind: [record] }`, see
    /// `docs/API.md` → `infra_get`), filled in by the engine only in report snapshots.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub infra: Value,
}

/// Snapshot keys read by the UI screens (the demo backend `SNAP_KEYS` plus `settings` and `scan`).
pub const SNAPSHOT_KEYS: &[&str] = &[
    "project", "scope", "docs", "people", "emails", "phones", "patterns", "hosts", "pcs",
    "software", "paths", "printers", "secrets", "findings", "gps", "events", "scans", "reports",
    "leaks", "settings", "scan",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_masked_in_debug_display() {
        let s = SecretValue::new("Kont0so#2024!");
        assert_eq!(format!("{s}"), "Ko…4!");
        assert!(!format!("{s:?}").contains("Kont0so"));
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"Kont0so#2024!\"");
        assert_eq!(SecretValue::new("short").masked(), "••••");
    }

    #[test]
    fn snapshot_has_contract_keys() {
        let v = serde_json::to_value(Snapshot::default()).unwrap();
        for k in SNAPSHOT_KEYS {
            assert!(v.get(k).is_some(), "missing key {k}");
        }
        let e = Event {
            y: 2024,
            m: "03".into(),
            reference: EventRef {
                kind: "doc".into(),
                id: 1,
            },
            ..Default::default()
        };
        let v = serde_json::to_value(e).unwrap();
        assert_eq!(v["ref"]["type"], "doc");
        let sw = Software {
            cves: vec![("CVE-1".into(), 9.8)],
            ..Default::default()
        };
        assert_eq!(serde_json::to_value(sw).unwrap()["cves"][0][0], "CVE-1");
    }

    #[test]
    fn secret_marker_escape_roundtrips_all_edge_cases() {
        for raw in [
            "plain_secret",
            r"C:\Users\alice\pass",
            "p@ss}}word",
            "tail}}",
            "single}",
            "triple}}}",
            r"a\}b",
            r"a\\}b",
            r"end\}",
        ] {
            let esc = escape_secret_marker(raw);
            let wrapped = format!("{esc}}}}}_tail");
            let end = find_secret_marker_end(&wrapped).unwrap();
            assert_eq!(&wrapped[end..], "}}_tail", "for {raw:?}");
            assert_eq!(unescape_secret_marker(&wrapped[..end]), raw, "for {raw:?}");
        }
    }
}
