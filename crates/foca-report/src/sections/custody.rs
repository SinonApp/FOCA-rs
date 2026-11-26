//! Chain of Custody (`custody`) and SHA-256 verification helpers for FOCA-rs reports.
//!
//! When [`crate::opts::ReportOptions::custody`] is enabled, HTML, Markdown and DOCX reports
//! embed a tamper-evident metadata block (`Custody` section with the deterministic inputs digest
//! `inputs_sha256`, scope, scan provenance and verification instructions), while `foca-engine`
//! writes detached `<report>.sha256` (`sha256sum` compatible) and `<report>.sig.json` manifest
//! sidecars. When `custody` is `false`, rendered report bytes are completely unchanged.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use foca_core::api::Snapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::data::{self, RequestEntry};
use crate::mask;
use crate::opts::{Lang, ReportOptions};
use crate::safe::{html as esc, md as mesc};
use crate::Ctx;

/// Computes lowercase hex SHA-256 of raw bytes using pure-Rust `sha2`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Summary of one contributing scan inside the Chain of Custody record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyScan {
    pub id: String,
    pub profile: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub egress: String,
}

/// Tamper-evident Chain of Custody metadata attached alongside or inside a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRecord {
    pub schema: String,
    pub report_file: String,
    pub report_sha256: String,
    pub inputs_sha256: String,
    pub report_bytes: usize,
    pub generated_at: String,
    pub generator: String,
    pub project: String,
    pub client: String,
    pub template: String,
    pub format: String,
    pub lang: String,
    pub secrets_mode: String,
    pub scope_targets: Vec<String>,
    pub scope_excludes: Vec<String>,
    pub findings_total: u32,
    pub docs_total: u32,
    pub requests_total: u32,
    pub scans: Vec<CustodyScan>,
}

/// Cryptographic signature block embedded in `.sig.json` when a platform `ReportSigner` signs
/// the Chain of Custody payload (for example AndroidKeyStore ECDSA P-256).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodySignature {
    pub alg: String,
    pub key_alias: String,
    pub sig_b64: String,
    pub pubkey_b64: String,
}

/// Detached JSON manifest (`<report>.sig.json`) combining custody metadata and optional signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyManifest {
    pub schema: String,
    pub payload_sha256: String,
    pub custody: CustodyRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<CustodySignature>,
}

/// Standard `sha256sum`-compatible single-line sidecar: `<64-hex>  <file_name>\n`.
pub fn format_sha256_sidecar(sha256: &str, file_name: &str) -> String {
    let clean_name: String = file_name.chars().filter(|c| !c.is_control()).collect();
    format!("{sha256}  {clean_name}\n")
}

/// Parses a `sha256sum`-compatible sidecar line and returns lowercase 64-char hex digest.
pub fn parse_sha256_sidecar(text: &str, expected_name: Option<&str>) -> Option<String> {
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let hex = parts.next()?.trim();
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if let Some(exp) = expected_name {
            let name = parts.next().unwrap_or("").trim().trim_start_matches('*');
            if !name.is_empty() && name != exp {
                continue;
            }
        }
        return Some(hex.to_ascii_lowercase());
    }
    None
}

/// Canonical byte serialization signed by `ReportSigner` (`signature` covers this exact payload).
pub fn sign_payload(rec: &CustodyRecord) -> Vec<u8> {
    serde_json::to_vec(rec).unwrap_or_default()
}

/// Deterministic digest over redacted project inputs, document summaries, finding ids and scan ids.
/// Only the inputs are hashed: the generation time and the output format are left out, so the
/// same snapshot yields the same digest in every format and on every rebuild.
pub fn inputs_digest_of(
    snap: &Snapshot,
    red: &mask::Redactor,
    o: &ReportOptions,
    log_len: usize,
    findings_ids: &[u64],
) -> String {
    let mut doc_refs: Vec<(u64, String, &str, u64)> = snap
        .docs
        .iter()
        .filter(|d| !d.deleted)
        .map(|d| (d.id, red.text(&d.name), d.ext.as_str(), d.size))
        .collect();
    doc_refs.sort_by_key(|x| x.0);
    let mut scan_ids: Vec<(&str, &str)> = snap
        .scans
        .iter()
        .map(|s| (s.id.as_str(), s.status.as_str()))
        .collect();
    scan_ids.sort();
    let mut fids = findings_ids.to_vec();
    fids.sort();
    let targets: Vec<String> = snap.scope.targets.iter().map(|t| red.text(&t.v)).collect();
    let excludes: Vec<String> = snap.scope.excl.iter().map(|e| red.text(e)).collect();

    let canonical = serde_json::json!({
        "schema": "foca-custody-inputs/v2",
        "generator": crate::GENERATOR,
        "project": red.text(&snap.project.name),
        "client": red.text(&snap.scope.client),
        "template": o.tpl.id(),
        "lang": o.lang.code(),
        "secrets_mode": o.secrets.id(),
        "targets": targets,
        "excludes": excludes,
        "scans": scan_ids,
        "doc_refs": doc_refs,
        "finding_ids": fids,
        "requests_total": log_len,
    });
    sha256_hex(&serde_json::to_vec(&canonical).unwrap_or_default())
}

/// Builds a redacted [`CustodyRecord`] from raw snapshot inputs (works across all formats).
pub fn build_record_for(
    snap: &Snapshot,
    log: &[RequestEntry],
    o: &ReportOptions,
    file_name: &str,
    report_bytes: &[u8],
    now: OffsetDateTime,
) -> CustodyRecord {
    let sel = data::select(snap, o);
    let pages = data::pages_estimate(o, sel.main.len(), sel.fixed.len());
    let res = data::ResultSnapshot::build(snap, &sel, pages);
    let red = mask::Redactor::new(snap, o.secrets, o.lang);
    let generated_at = now
        .replace_nanosecond(0)
        .unwrap_or(now)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let inputs_sha256 = inputs_digest_of(snap, &red, o, log.len(), &res.finding_ids);
    let report_sha256 = sha256_hex(report_bytes);
    let scans = snap
        .scans
        .iter()
        .map(|s| CustodyScan {
            id: red.text(&s.id),
            profile: if s.profile.is_empty() {
                red.text(&s.profile_id)
            } else {
                red.text(&s.profile)
            },
            started_at: s.started_at.clone(),
            finished_at: s.finished_at.clone(),
            status: red.text(&s.status),
            egress: red.text(&s.egress),
        })
        .collect();

    CustodyRecord {
        schema: "foca-custody/v1".into(),
        report_file: file_name.to_string(),
        report_sha256,
        inputs_sha256,
        report_bytes: report_bytes.len(),
        generated_at,
        generator: crate::GENERATOR.to_string(),
        project: red.text(&snap.project.name),
        client: red.text(&snap.scope.client),
        template: o.tpl.id().to_string(),
        format: o.fmt.ext().to_string(),
        lang: o.lang.code().to_string(),
        secrets_mode: o.secrets.id().to_string(),
        scope_targets: snap.scope.targets.iter().map(|t| red.text(&t.v)).collect(),
        scope_excludes: snap.scope.excl.iter().map(|e| red.text(e)).collect(),
        findings_total: res.total,
        docs_total: snap.docs.iter().filter(|d| !d.deleted).count() as u32,
        requests_total: log.len() as u32,
        scans,
    }
}

pub(crate) use crate::i18n::CustodyLabels;

pub(crate) fn labels(lang: Lang) -> CustodyLabels {
    crate::i18n::bundle(lang).custody
}

pub(crate) fn custody_rows(c: &Ctx) -> Vec<(String, String)> {
    let l = labels(c.o.lang);
    let ts = c.iso_time();
    let digest = inputs_digest_of(c.snap, &c.red, c.o, c.log.len(), &c.res.finding_ids);
    let fname = crate::report_file_name(
        c.snap,
        c.o,
        c.o.version.unwrap_or_else(|| crate::next_version(c.snap)),
    );
    let docs_live = c.snap.docs.iter().filter(|d| !d.deleted).count();
    let scans_line = if c.snap.scans.is_empty() {
        "0".to_string()
    } else {
        let mut by_id: BTreeMap<&str, &str> = BTreeMap::new();
        for s in &c.snap.scans {
            by_id.insert(s.id.as_str(), s.status.as_str());
        }
        format!(
            "{} ({})",
            c.snap.scans.len(),
            by_id
                .into_iter()
                .take(4)
                .map(|(id, st)| format!("{}: {}", c.r(id), c.r(st)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    vec![
        (l.generated_at.into(), ts),
        (l.generator.into(), crate::GENERATOR.into()),
        (l.inputs_digest.into(), digest),
        (
            l.findings_docs_reqs.into(),
            format!("{} / {} / {}", c.res.total, docs_live, c.log.len()),
        ),
        (l.scans_count.into(), scans_line),
        (l.secrets_policy.into(), c.secret_mode().into()),
        (
            l.sidecar_label.into(),
            format!("{fname}.sha256, {fname}.sig.json"),
        ),
    ]
}

pub(crate) fn render_html(c: &Ctx, h: &mut String) {
    let l = labels(c.o.lang);
    let _ = writeln!(
        h,
        "<section id=\"custody\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>",
        esc(l.title),
        esc(l.subtitle)
    );
    h.push_str("<dl class=\"kv\">");
    for (k, v) in custody_rows(c) {
        let _ = write!(h, "<dt>{}</dt><dd class=\"mono\">{}</dd>", esc(&k), esc(&v));
    }
    let _ = writeln!(
        h,
        "</dl>\n<p class=\"muted\">{}</p>\n</section>",
        esc(l.verify_hint)
    );
}

pub(crate) fn render_md(c: &Ctx, o: &mut String) {
    let l = labels(c.o.lang);
    let _ = writeln!(o, "## {}\n", mesc(l.title));
    let _ = writeln!(o, "*{}*\n", mesc(l.subtitle));
    for (k, v) in custody_rows(c) {
        let _ = writeln!(o, "- **{}:** {}", mesc(&k), crate::safe::md_code_span(&v));
    }
    let _ = writeln!(o, "\n> {}\n", mesc(l.verify_hint));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_sidecar_roundtrip_and_parse() {
        let data = b"hello foca report";
        let hex = sha256_hex(data);
        assert_eq!(hex.len(), 64);
        assert_eq!(
            hex,
            "44514e177c130e4b39e9f355a1f0174a6c5a7eaac4c03ef9b0a09834bc0b11de"
        );
        let sidecar = format_sha256_sidecar(&hex, "Report_test_v1.html");
        assert_eq!(sidecar, format!("{hex}  Report_test_v1.html\n"));
        assert_eq!(
            parse_sha256_sidecar(&sidecar, Some("Report_test_v1.html")),
            Some(hex.clone())
        );
        assert_eq!(parse_sha256_sidecar(&sidecar, Some("other.html")), None);
        assert_eq!(parse_sha256_sidecar("not-a-hash  file", None), None);
    }
}
