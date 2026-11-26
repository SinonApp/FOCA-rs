//! Infrastructure subsections of the hosts section (1.2 modules), taken from `snapshot.infra`
//! (`{ kind: [record] }`, see `docs/API.md` → `infra_get`): certificates and their audit, mail
//! policies, SaaS / clouds (services, Microsoft 365 tenant, CDN) and out-of-scope candidates.
//! Rendered only when there are records; strings go through the redactor (`Ctx::h` / `Ctx::m`).

use std::fmt::Write as _;

use serde_json::{json, Value};

use crate::i18n::{infra_strings, InfraT};
use crate::safe::{html as esc, md as mesc};
use crate::Ctx;

fn list<'a>(c: &'a Ctx, kind: &str) -> Vec<&'a Value> {
    c.snap.infra[kind]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn s(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(x) => x.clone(),
        x => x.to_string(),
    }
}

fn trust(t: &InfraT, v: &Value) -> String {
    match v["status"].as_str().or(v.as_str()) {
        Some("trusted") => t.trusted.into(),
        Some("self_signed") => t.self_signed.into(),
        Some("unknown_ca") => t.unknown_ca.into(),
        Some("incomplete_chain") => t.incomplete.into(),
        Some("invalid") => t.invalid.into(),
        _ => "-".into(),
    }
}

fn cert_rows(c: &Ctx, t: &InfraT) -> Vec<[String; 6]> {
    list(c, "cert")
        .into_iter()
        .map(|r| {
            let leaf = &r["chain"][0];
            let issuer = leaf["issuer"]["cn"]
                .as_str()
                .or(leaf["issuer"]["text"].as_str())
                .unwrap_or("");
            let days = r["days_left"]
                .as_i64()
                .map(|d| format!("{d} {}", t.days))
                .unwrap_or_default();
            let mode = match r["mode"].as_str().unwrap_or("tls") {
                "starttls" => "STARTTLS",
                "no_sni" => t.no_sni,
                "legacy" => "TLS 1.0/1.1",
                _ => "TLS",
            };
            let issues: Vec<String> = r["issues"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|i| i["code"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            [
                format!("{}:{}", s(&r["host"]), s(&r["port"])),
                format!("{mode} {}", s(&r["version"])).trim().to_string(),
                issuer.to_string(),
                days,
                trust(t, &r["trust"]),
                issues.join(", "),
            ]
        })
        .collect()
}

fn mail_rows(c: &Ctx, t: &InfraT) -> Vec<[String; 6]> {
    let yes_no = |b: bool| if b { t.yes } else { t.no }.to_string();
    list(c, "mail_policy")
        .into_iter()
        .map(|r| {
            let dom = r["caa"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x["value"].as_str().map(String::from))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            [
                s(&r["domain"]),
                r["mta_sts_policy"]["mode"]
                    .as_str()
                    .map(String::from)
                    .unwrap_or_else(|| yes_no(!r["mta_sts"].is_null())),
                yes_no(!r["tls_rpt"].is_null()),
                yes_no(!r["bimi"].is_null()),
                if dom.is_empty() {
                    t.no.to_string()
                } else {
                    dom
                },
                s(&r["dnssec"]),
            ]
        })
        .collect()
}

fn saas_rows(c: &Ctx) -> Vec<[String; 3]> {
    let mut out: Vec<[String; 3]> = list(c, "saas")
        .into_iter()
        .filter(|r| r["hits"].as_array().is_some_and(|a| !a.is_empty()))
        .map(|r| {
            // Order-preserving dedup: one provider may be detected by several signals
            // (MX, TXT verification, CNAME) that are not adjacent.
            let mut names: Vec<String> = Vec::new();
            for n in r["hits"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|h| h["name"].as_str())
            {
                if !names.iter().any(|x| x == n) {
                    names.push(n.to_string());
                }
            }
            [s(&r["domain"]), "SaaS".into(), names.join(", ")]
        })
        .collect();
    for r in list(c, "tenant") {
        let tid = s(&r["openid"]["tenant_id"]);
        let ns = s(&r["realm"]["namespace"]);
        out.push([
            s(&r["domain"]),
            "Microsoft 365".into(),
            format!("{tid} {ns} {}", s(&r["federation_host"]))
                .trim()
                .to_string(),
        ]);
    }
    let mut cdn: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for r in list(c, "cdn") {
        cdn.entry(s(&r["name"])).or_default().push(s(&r["host"]));
    }
    for (p, hs) in cdn {
        out.push([hs.join(", "), "CDN / cloud".into(), p]);
    }
    out
}

fn oos_rows(c: &Ctx, t: &InfraT) -> Vec<[String; 3]> {
    list(c, "oos")
        .into_iter()
        .map(|r| {
            let kind = match r["kind"].as_str().unwrap_or("") {
                "san" => t.k_san,
                "org_pivot" => t.k_org,
                "tenant_domain" => t.k_tenant,
                "origin_ip" => t.k_origin,
                "ptr" => "PTR",
                _ => t.k_fed,
            };
            [s(&r["host"]), kind.to_string(), s(&r["via"])]
        })
        .collect()
}

fn html_table<const N: usize>(c: &Ctx, h: &mut String, head: [&str; N], rows: &[[String; N]]) {
    h.push_str("<table><thead><tr>");
    for th in head {
        let _ = write!(h, "<th>{}</th>", esc(th));
    }
    h.push_str("</tr></thead><tbody>\n");
    for r in rows {
        h.push_str("<tr>");
        for cell in r {
            let _ = write!(h, "<td>{}</td>", c.h(cell));
        }
        h.push_str("</tr>\n");
    }
    h.push_str("</tbody></table>\n");
}

fn md_table<const N: usize>(c: &Ctx, o: &mut String, head: [&str; N], rows: &[[String; N]]) {
    let _ = writeln!(
        o,
        "| {} |\n|{}",
        head.iter().map(|x| mesc(x)).collect::<Vec<_>>().join(" | "),
        "---|".repeat(N)
    );
    for r in rows {
        let _ = writeln!(
            o,
            "| {} |",
            r.iter().map(|x| c.m(x)).collect::<Vec<_>>().join(" | ")
        );
    }
    o.push('\n');
}

/// HTML: certificates, mail, SaaS/clouds and out-of-scope candidates.
pub(crate) fn html(c: &Ctx, h: &mut String) {
    if c.snap.infra.is_null() {
        return;
    }
    let t = infra_strings(c.o.lang);
    let certs = cert_rows(c, t);
    if !certs.is_empty() {
        let _ = write!(h, "<h3 id=\"certs\">{}</h3>", esc(t.certs));
        html_table(
            c,
            h,
            [t.endpoint, t.protocol, t.issuer, t.valid, t.trust, t.issues],
            &certs,
        );
    }
    let mail = mail_rows(c, t);
    if !mail.is_empty() {
        let _ = write!(h, "<h3 id=\"mail\">{}</h3>", esc(t.mail));
        html_table(
            c,
            h,
            [t.domain, "MTA-STS", "TLS-RPT", "BIMI", "CAA", "DNSSEC"],
            &mail,
        );
    }
    let saas = saas_rows(c);
    if !saas.is_empty() {
        let _ = write!(h, "<h3 id=\"saas\">{}</h3>", esc(t.saas));
        html_table(c, h, [t.object, t.kind, t.services], &saas);
    }
    let oos = oos_rows(c, t);
    if !oos.is_empty() {
        let _ = write!(
            h,
            "<h3 id=\"oos\">{}</h3><p class=\"muted\">{}</p>",
            esc(t.oos),
            esc(t.oos_note)
        );
        html_table(c, h, [t.object, t.kind, t.via], &oos);
    }
}

/// Markdown: the same subsections.
pub(crate) fn md(c: &Ctx, o: &mut String) {
    if c.snap.infra.is_null() {
        return;
    }
    let t = infra_strings(c.o.lang);
    let certs = cert_rows(c, t);
    if !certs.is_empty() {
        let _ = writeln!(o, "### {}\n", mesc(t.certs));
        md_table(
            c,
            o,
            [t.endpoint, t.protocol, t.issuer, t.valid, t.trust, t.issues],
            &certs,
        );
    }
    let mail = mail_rows(c, t);
    if !mail.is_empty() {
        let _ = writeln!(o, "### {}\n", mesc(t.mail));
        md_table(
            c,
            o,
            [t.domain, "MTA-STS", "TLS-RPT", "BIMI", "CAA", "DNSSEC"],
            &mail,
        );
    }
    let saas = saas_rows(c);
    if !saas.is_empty() {
        let _ = writeln!(o, "### {}\n", mesc(t.saas));
        md_table(c, o, [t.object, t.kind, t.services], &saas);
    }
    let oos = oos_rows(c, t);
    if !oos.is_empty() {
        let _ = writeln!(o, "### {}\n\n_{}_\n", mesc(t.oos), mesc(t.oos_note));
        md_table(c, o, [t.object, t.kind, t.via], &oos);
    }
}

/// DOCX: certificates, mail policies, SaaS/clouds and out-of-scope candidates.
pub(crate) fn doc_tables(c: &Ctx) -> Vec<crate::table::DocTable> {
    use crate::table::DocTable;
    if c.snap.infra.is_null() {
        return Vec::new();
    }
    let t = infra_strings(c.o.lang);
    let red = |rows: Vec<Vec<String>>| -> Vec<Vec<String>> {
        rows.into_iter()
            .map(|r| r.iter().map(|x| c.r(x)).collect())
            .collect()
    };
    let mut out = Vec::new();
    let certs = cert_rows(c, t);
    if !certs.is_empty() {
        out.push(DocTable::new(
            t.certs,
            None,
            &[t.endpoint, t.protocol, t.issuer, t.valid, t.trust, t.issues],
            red(certs.into_iter().map(Vec::from).collect()),
        ));
    }
    let mail = mail_rows(c, t);
    if !mail.is_empty() {
        out.push(DocTable::new(
            t.mail,
            None,
            &[t.domain, "MTA-STS", "TLS-RPT", "BIMI", "CAA", "DNSSEC"],
            red(mail.into_iter().map(Vec::from).collect()),
        ));
    }
    let saas = saas_rows(c);
    if !saas.is_empty() {
        out.push(DocTable::new(
            t.saas,
            None,
            &[t.object, t.kind, t.services],
            red(saas.into_iter().map(Vec::from).collect()),
        ));
    }
    let oos = oos_rows(c, t);
    if !oos.is_empty() {
        out.push(DocTable::new(
            t.oos,
            Some(t.oos_note.to_string()),
            &[t.object, t.kind, t.via],
            red(oos.into_iter().map(Vec::from).collect()),
        ));
    }
    out
}

/// JSON report: the `infra` block, only when there is data.
pub(crate) fn json(c: &Ctx) -> Value {
    if c.snap.infra.is_null() {
        return Value::Null;
    }
    let t = infra_strings(c.o.lang);
    json!({
        "certs": cert_rows(c, t), "mail": mail_rows(c, t), "saas": saas_rows(c), "oos": oos_rows(c, t),
    })
}
