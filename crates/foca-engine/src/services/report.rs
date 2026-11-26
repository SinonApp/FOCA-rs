//! Reports and export via foca-report (feature `report`).

use foca_core::api::Snapshot;
use foca_report::{
    build_report_with_visuals, export_with_log, tpl_label, ExportFormat, ExportKind, ExportOptions,
    ReportOptions, RequestEntry, Visuals,
};
use serde_json::Value;

use crate::{BuiltExport, BuiltReport, CmdError, ReportBuilder};

/// foca-report based builder: HTML/MD/CSV/JSON reports and exports (wordlists, CSV, JSON, Maltego).
pub struct FocaReport;

fn log_entries(log: &[foca_store::RequestLog]) -> Vec<RequestEntry> {
    log.iter()
        .map(|r| RequestEntry {
            time: r.time.clone(),
            scan_id: r.scan_id.clone(),
            module: r.module.clone(),
            method: r.method.clone(),
            url: r.url.clone(),
            host: r.host.clone(),
            status: r.status,
            bytes: r.bytes,
            active: r.active,
            blocked: RequestEntry::is_blocked_code(r.error.as_deref()),
            error: r.error.clone(),
            note: r.note.clone(),
            ctype: r.ctype.clone(),
        })
        .collect()
}

impl ReportBuilder for FocaReport {
    fn build_report(
        &self,
        snap: &Snapshot,
        log: &[foca_store::RequestLog],
        visuals: &Value,
        opts: &Value,
        now: time::OffsetDateTime,
    ) -> Result<BuiltReport, CmdError> {
        let o = ReportOptions::from_ui(opts);
        let vis: Visuals = if visuals.is_null() {
            Visuals::default()
        } else {
            serde_json::from_value(visuals.clone()).unwrap_or_default()
        };
        let entries = log_entries(log);
        let a = build_report_with_visuals(snap, &entries, &vis, &o, now);
        let rec =
            foca_report::custody::build_record_for(snap, &entries, &o, &a.file_name, &a.bytes, now);
        let custody_payload = foca_report::custody::sign_payload(&rec);
        let custody = serde_json::to_value(&rec).ok();
        // The UI label is kept for the classic templates; the new ones always get their own.
        let label = opts
            .get("tpl")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && !o.tpl.is_standalone())
            .map(String::from)
            .unwrap_or_else(|| tpl_label(o.tpl, o.lang).to_string());
        let record = a.report_record(0, "", &label);
        Ok(BuiltReport {
            file_name: a.file_name.clone(),
            bytes: a.bytes,
            record,
            custody,
            custody_payload,
        })
    }

    fn export(
        &self,
        snap: &Snapshot,
        log: &[foca_store::RequestLog],
        kind: &str,
        fmt: &str,
        opts: &Value,
    ) -> Result<BuiltExport, CmdError> {
        let k = ExportKind::parse(kind)
            .ok_or_else(|| CmdError::new("bad_args", format!("вид экспорта {kind}")))?;
        let f = ExportFormat::from_ui(fmt, opts)
            .ok_or_else(|| CmdError::new("bad_args", format!("формат экспорта {fmt}")))?;
        let o = ExportOptions::from_ui(opts);
        let a = export_with_log(snap, &log_entries(log), k, f, &o);
        Ok(BuiltExport {
            bytes: a.bytes,
            file_name: a.file_name,
            count: a.count,
            secrets: a.secrets,
            pii_redacted: a.pii_redacted,
        })
    }
}
