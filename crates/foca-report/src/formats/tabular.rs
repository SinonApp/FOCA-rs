//! CSV report (RFC 4180, UTF-8 BOM, CSV injection protection) and JSON report
//! (`schema/report.v1.json`).

use foca_core::api::Finding;
use serde_json::{json, Map, Value};

use crate::data::{sev_id, status_id};
use crate::safe::csv_row;
use crate::Ctx;

/// CSV report columns; kept stable because client spreadsheets depend on them.
pub(crate) const CSV_COLUMNS: &[&str] = &[
    "id",
    "section",
    "severity",
    "severity_label",
    "status",
    "title",
    "host",
    "category",
    "mitre",
    "cve",
    "cvss",
    "description",
    "evidence",
    "recommendation",
    "url",
    "rule",
    "documents",
    "first_scan",
    "fixed_scan",
];

fn finding_row(c: &Ctx, f: &Finding, section: &str) -> Vec<String> {
    let docs: Vec<String> = f.provenance.docs.iter().map(|d| c.doc_name(*d)).collect();
    vec![
        format!("F-{}", f.id),
        section.into(),
        sev_id(f.sev).into(),
        c.sev(f.sev).into(),
        status_id(f.status).into(),
        c.r(&f.title),
        c.r(&f.host),
        c.r(&f.category),
        c.r(&f.mitre),
        c.r(&f.cve.join(" ")),
        f.cvss.map(|v| format!("{v:.1}")).unwrap_or_default(),
        c.r(&f.description),
        c.r(&f.evidence),
        c.r(&f.recommendation),
        c.r(f.url.as_deref().unwrap_or("")),
        c.r(&f.provenance.rule),
        c.r(&docs.join("; ")),
        c.r(f.first_scan.as_deref().unwrap_or("")),
        c.r(f.fixed_scan.as_deref().unwrap_or("")),
    ]
}

pub(crate) fn report_csv(c: &Ctx) -> Vec<u8> {
    let mut s = String::from("\u{feff}");
    s.push_str(&csv_row(CSV_COLUMNS, ','));
    for f in &c.main {
        s.push_str(&csv_row(&finding_row(c, f, "main"), ','));
    }
    for f in &c.fixed {
        s.push_str(&csv_row(&finding_row(c, f, "fixed"), ','));
    }
    s.into_bytes()
}

/// Passes every string value of the tree through secret masking.
pub(crate) fn redact_value(v: &mut Value, f: &dyn Fn(&str) -> String) {
    match v {
        Value::String(s) => *s = f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| redact_value(x, f)),
        Value::Object(o) => o.values_mut().for_each(|x| redact_value(x, f)),
        _ => {}
    }
}

fn finding_json(c: &Ctx, f: &Finding) -> Value {
    json!({
        "id": f.id,
        "title": f.title,
        "severity": sev_id(f.sev),
        "severity_label": c.sev(f.sev),
        "status": status_id(f.status),
        "host": f.host,
        "category": f.category,
        "source": f.source,
        "module": f.module,
        "active": f.active,
        "time": f.time,
        "first_scan": f.first_scan,
        "fixed_scan": f.fixed_scan,
        "tags": f.tags,
        "cve": f.cve,
        "cvss": f.cvss.map(|v| (v as f64 * 10.0).round() / 10.0),
        "mitre": f.mitre,
        "description": f.description,
        "evidence": f.evidence,
        "recommendation": f.recommendation,
        "url": f.url,
        "documents": f.provenance.docs.iter().map(|d| json!({ "id": d, "name": c.doc_name(*d) })).collect::<Vec<_>>(),
        "provenance": { "rule": f.provenance.rule, "fields": f.provenance.fields },
        "notes": f.notes.iter().map(|n| json!({ "who": n.who, "time": n.time, "text": n.text })).collect::<Vec<_>>(),
    })
}

fn pairs(v: &[(String, u32)], k: &str) -> Vec<Value> {
    v.iter().map(|(a, n)| json!({ k: a, "count": n })).collect()
}

pub(crate) fn report_json(c: &Ctx) -> String {
    let snap = c.snap;
    let s = &c.o.sections;
    let ov = &c.ov;
    let on = |b: bool, v: Vec<Value>| if b { v } else { Vec::new() };
    let mut v = json!({
        "schema_version": crate::SCHEMA_VERSION,
        "schema": "foca-report/v1",
        "generator": crate::GENERATOR,
        "generated_at": c.iso_time(),
        "report": {
            "template": c.o.tpl.id(),
            "lang": c.o.lang.code(),
            "sections": c.o.sections,
            "filters": {
                "confirmed": c.o.confirmed,
                "min_sev": c.o.min_sev.map(sev_id),
                "picked_only": c.o.picked_only,
                "picked": c.o.picked,
            },
            "secrets": c.o.secrets.id(),
            "company": c.o.company,
        },
        "project": {
            "id": snap.project.id,
            "name": snap.project.name,
            "client": snap.project.client,
            "domain": snap.project.domain,
        },
        "scope": {
            "client": snap.scope.client,
            "contact": snap.scope.contact,
            "basis": snap.scope.basis,
            "targets": snap.scope.targets.iter().map(|t| json!({ "value": t.v, "type": t.kind })).collect::<Vec<_>>(),
            "exclusions": snap.scope.excl,
        },
        "summary": {
            "risk": c.res.risk,
            "risk_level": c.res.risk_level,
            "project_risk": c.res.project_risk,
            "counts": c.res.counts,
            "total": c.res.total,
            "fixed": c.fixed.len(),
            "pages": c.res.pages,
        },
        "overview": {
            "docs_total": ov.docs_total,
            "docs_analyzed": ov.docs_analyzed,
            "docs_by_type": pairs(&ov.docs_by_type, "type"),
            "top_people": ov.top_people.iter().map(|(l, n, d)| json!({ "login": l, "name": n, "docs": d })).collect::<Vec<_>>(),
            "top_software": pairs(&ov.top_software, "name"),
            "eol_software": ov.eol_software.iter().map(|(n, d, cve)| json!({ "name": n, "eol_date": d, "cve": cve })).collect::<Vec<_>>(),
            "people": ov.people,
            "emails": ov.emails,
            "hosts": ov.hosts,
            "hosts_internal": ov.hosts_internal,
            "pcs": ov.pcs,
            "servers": ov.servers,
            "printers": ov.printers,
            "paths": ov.paths,
            "software": ov.software,
            "secrets": ov.secrets,
        },
        "findings": on(s.findings, c.main.iter().map(|f| finding_json(c, f)).collect()),
        "fixed": on(s.fixed, c.fixed.iter().map(|f| finding_json(c, f)).collect()),
        "people": on(s.people, snap.people.iter().map(|p| json!({
            "login": p.login, "name": p.name, "role": p.role, "pc": p.pc, "emails": p.emails,
            "aliases": p.aliases, "docs": p.docs, "service": p.service,
        })).collect()),
        "emails": on(s.people, snap.emails.iter().map(|e| json!({
            "addr": e.addr, "name": e.name, "login": e.login, "found": e.found, "source": e.src,
        })).collect()),
        "hosts": on(s.infra, snap.hosts.iter().map(|h| json!({
            "name": h.name, "ip": h.ip, "role": h.role, "tech": h.tech, "internal": h.internal,
            "scope": h.scope, "source": h.source,
        })).collect()),
        "pcs": on(s.infra, snap.pcs.iter().map(|p| json!({
            "name": p.name, "type": p.kind, "users": p.users, "ip": p.ip, "docs": p.docs,
        })).collect()),
        "software": on(s.infra, snap.software.iter().map(|x| json!({
            "id": x.id, "name": x.name, "version": x.ver, "eol": x.eol, "eol_date": x.eol_date,
            "cve": x.cve, "docs": x.docs,
        })).collect()),
        "paths": on(s.infra, snap.paths.iter().map(|p| json!({
            "path": p.path, "user": p.user, "host": p.host, "docs": p.docs,
        })).collect()),
        "documents": on(s.docs, snap.docs.iter().filter(|d| !d.deleted).map(|d| json!({
            "id": d.id, "name": d.name, "ext": d.ext, "url": d.url, "title": d.title,
            "author": d.author, "software": d.software, "created": d.created_at,
            "modified": d.modified_at, "size": d.size, "status": d.status, "flags": d.flags,
        })).collect()),
        "secrets": on(s.appx, snap.secrets.iter().filter(|x| x.kind != "host").map(|x| json!({
            "id": x.id, "type": x.kind, "doc": x.doc, "location": x.location,
            "severity": sev_id(x.sev), "value": c.red.mask(x.value.expose()), "finding": x.finding,
        })).collect()),
        "request_log": {
            "total": c.ls.total,
            "passive": c.ls.passive,
            "active": c.ls.active,
            "blocked": c.ls.blocked,
            "errors": c.ls.errors,
            "hosts": c.ls.hosts,
            "hosts_target": c.ls.hosts_target,
            "hosts_third": c.ls.hosts_third,
            "first": c.ls.first,
            "last": c.ls.last,
            "by_module": pairs(&c.ls.by_module, "module"),
            "requests": on(s.log, c.log.iter().filter(|r| r.active || r.blocked).map(|r| json!({
                "time": r.time, "scan_id": r.scan_id, "module": r.module, "method": r.method,
                "url": r.url, "host": r.host, "status": r.status, "bytes": r.bytes,
                "active": r.active, "blocked": r.blocked, "error": r.error,
                "note": r.note, "ctype": r.ctype,
            })).collect()),
        },
    });
    // Website and technologies (site recon), only when there is data (keeps golden files
    // without recon stable).
    let web = crate::sections::recon::json(c);
    if s.infra && !web.is_null() {
        v["website"] = web;
    }
    // Host port table (own scan + InternetDB cache), only when there is data.
    let ports = crate::sections::ports::json(c);
    if s.infra && !ports.is_null() {
        v["ports"] = ports;
    }
    // Certificates, mail policies, SaaS/clouds and out-of-scope candidates, only when there is data.
    let infra = crate::sections::infra::json(c);
    if s.infra && !infra.is_null() {
        v["infra"] = infra;
    }
    // Mask secrets in every string (`secrets[].value` is already in the display mode).
    redact_value(&mut v, &|s| c.r(s));
    let mut out = serde_json::to_string_pretty(&sorted(v)).unwrap_or_default();
    out.push('\n');
    out
}

/// Sorts object keys alphabetically (stable output for diffs and golden tests).
pub(crate) fn sorted(v: Value) -> Value {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<(String, Value)> = o.into_iter().collect();
            keys.sort_by(|a, b| a.0.cmp(&b.0));
            let mut m = Map::new();
            for (k, v) in keys {
                m.insert(k, sorted(v));
            }
            Value::Object(m)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        x => x,
    }
}
