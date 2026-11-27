//! Contextual remediation playbooks (`finding_playbook`) localized in Ukrainian, Russian and
//! English via `locales/{en,ru,uk}/playbooks.json`.
//!
//! Each finding maps by `provenance.rule` (or category fallback) to remediation steps,
//! owner roles, safe verification commands contextualized to the finding's sanitized host, URL,
//! port, CVEs and source documents, and standard references from [`crate::standards::Standards`].
//! Finding evidence is never interpolated so raw secrets and PII never enter remediation output.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use foca_core::api::Finding;
use foca_core::Lang;
use serde::{Deserialize, Serialize};

use crate::standards::Standards;

/// One remediation step of a playbook. `title` carries no number: the UI numbers steps by `step`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub step: u8,
    pub title: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub owner: String,
}

/// Localized remediation playbook for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Playbook {
    pub rule: String,
    pub playbook_key: String,
    pub lang: String,
    /// Localized name of `playbook_key`.
    pub key_label: String,
    pub title: String,
    pub summary: String,
    /// Effort code: `quick` | `medium` | `planned`.
    pub effort: String,
    /// Localized name of `effort`.
    pub effort_label: String,
    pub steps: Vec<PlaybookStep>,
    pub verify: Vec<String>,
    pub references: Vec<String>,
    pub disclaimer: String,
}

#[derive(Debug, Deserialize)]
struct StepTpl {
    title: String,
    action: String,
    command: Option<String>,
    owner: String,
}

#[derive(Debug, Deserialize)]
struct PlaybookTpl {
    key: String,
    title: String,
    summary: String,
    effort: String,
    steps: Vec<StepTpl>,
    verify: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PlaybookLabels {
    effort: BTreeMap<String, String>,
    keys: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct PlaybookLocale {
    disclaimer: String,
    playbooks: BTreeMap<String, PlaybookTpl>,
    labels: PlaybookLabels,
}

fn locale_data(lang: Lang) -> &'static PlaybookLocale {
    static EN: OnceLock<PlaybookLocale> = OnceLock::new();
    static RU: OnceLock<PlaybookLocale> = OnceLock::new();
    static UK: OnceLock<PlaybookLocale> = OnceLock::new();
    match lang {
        Lang::En => EN.get_or_init(|| {
            serde_json::from_str(include_str!("../../../../locales/en/playbooks.json"))
                .expect("valid locales/en/playbooks.json")
        }),
        Lang::Ru => RU.get_or_init(|| {
            serde_json::from_str(include_str!("../../../../locales/ru/playbooks.json"))
                .expect("valid locales/ru/playbooks.json")
        }),
        Lang::Uk => UK.get_or_init(|| {
            serde_json::from_str(include_str!("../../../../locales/uk/playbooks.json"))
                .expect("valid locales/uk/playbooks.json")
        }),
    }
}

/// Contextual sanitized values derived solely from safe finding metadata (never `evidence`).
struct SafeCtx {
    host: String,
    domain: String,
    port: String,
    url: String,
    cve: String,
    docs: String,
}

impl SafeCtx {
    fn from_finding(f: &Finding, doc_names: &[String]) -> Self {
        let host = sanitize_token(&f.host, "target.example");
        let port = infer_port(f).unwrap_or(443).to_string();
        let url = sanitize_url(f.url.as_deref(), &host);
        let domain = sanitize_domain(&host);
        let cve = if f.cve.is_empty() {
            "CVE-check".into()
        } else {
            f.cve
                .iter()
                .take(4)
                .map(|c| sanitize_token(c, "CVE"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let docs = if doc_names.is_empty() {
            "-".into()
        } else {
            doc_names
                .iter()
                .take(3)
                .map(|d| sanitize_label(d))
                .collect::<Vec<_>>()
                .join(", ")
        };
        Self {
            host,
            domain,
            port,
            url,
            cve,
            docs,
        }
    }

    fn expand(&self, raw: &str) -> String {
        raw.replace("{host}", &self.host)
            .replace("{domain}", &self.domain)
            .replace("{port}", &self.port)
            .replace("{url}", &self.url)
            .replace("{cve}", &self.cve)
            .replace("{docs}", &self.docs)
    }
}

fn sanitize_token(s: &str, fallback: &str) -> String {
    let cleaned: String = s
        .trim()
        .chars()
        .take(128)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == ':' || c == '.');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn sanitize_label(s: &str) -> String {
    let cleaned: String = s
        .trim()
        .chars()
        .take(96)
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    c,
                    '`' | '$'
                        | ';'
                        | '|'
                        | '&'
                        | '<'
                        | '>'
                        | '\\'
                        | '('
                        | ')'
                        | '*'
                        | '?'
                        | '\''
                        | '"'
                        | '{'
                        | '}'
                        | '['
                        | ']'
                        | '!'
                        | '~'
                )
        })
        .collect();
    if cleaned.is_empty() {
        "document".into()
    } else {
        cleaned
    }
}

fn sanitize_url(raw: Option<&str>, host: &str) -> String {
    if let Some(u) = raw.map(str::trim).filter(|u| !u.is_empty()) {
        if let Ok(parsed) = reqwest_free_url(u) {
            return parsed;
        }
    }
    if host.contains(':') && host.parse::<std::net::IpAddr>().is_ok() {
        format!("https://[{host}]/")
    } else {
        format!("https://{host}/")
    }
}

fn reqwest_free_url(u: &str) -> Result<String, ()> {
    let lower = u.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(());
    }
    // Strip userinfo if present, and reject whitespace/shell characters.
    let (scheme, rest) = u.split_once("://").ok_or(())?;
    let rest = match rest.split_once('@') {
        Some((before_at, after_at)) if !before_at.contains('/') && !before_at.contains('?') => {
            after_at
        }
        _ => rest,
    };
    let clean: String = rest
        .chars()
        .take(200)
        .filter(|c| {
            !c.is_control()
                && !c.is_whitespace()
                && !matches!(
                    c,
                    '\'' | '"'
                        | '`'
                        | '$'
                        | ';'
                        | '|'
                        | '&'
                        | '<'
                        | '>'
                        | '\\'
                        | '('
                        | ')'
                        | '*'
                        | '?'
                        | '{'
                        | '}'
                        | '['
                        | ']'
                        | '!'
                        | '~'
                )
        })
        .collect();
    if clean.is_empty() {
        Err(())
    } else {
        Ok(format!("{scheme}://{clean}"))
    }
}

fn sanitize_domain(host: &str) -> String {
    let h = host.trim();
    if h.parse::<std::net::IpAddr>().is_ok() {
        return h.to_string();
    }
    if let Some(rest) = h.strip_prefix('[') {
        if let Some((ip, _)) = rest.split_once(']') {
            if ip.parse::<std::net::IpAddr>().is_ok() {
                return ip.to_string();
            }
        }
    }
    let h = match h.rsplit_once(':') {
        Some((head, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => h,
    };
    if h.parse::<std::net::IpAddr>().is_ok() {
        return h.to_string();
    }
    const PUBLIC_SECOND: &[&str] = &[
        "gov.ua", "com.ua", "org.ua", "net.ua", "edu.ua", "in.ua", "kiev.ua", "kyiv.ua", "co.uk",
        "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "com.br", "co.jp",
    ];
    let parts: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() >= 2 {
        let sfx = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        if PUBLIC_SECOND.contains(&sfx.to_ascii_lowercase().as_str()) {
            if parts.len() >= 3 {
                return format!("{}.{sfx}", parts[parts.len() - 3]);
            }
            return sfx;
        }
        return sfx;
    }
    h.to_string()
}

fn infer_port(f: &Finding) -> Option<u16> {
    if let Some(p) = f
        .host
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
    {
        return Some(p);
    }
    if let Some(u) = &f.url {
        let low = u.to_ascii_lowercase();
        if let Some(rest) = low
            .strip_prefix("https://")
            .or_else(|| low.strip_prefix("http://"))
        {
            let hp = rest.split('/').next().unwrap_or("");
            if let Some((_, p)) = hp.rsplit_once(':') {
                if let Ok(port) = p.parse::<u16>() {
                    return Some(port);
                }
            }
            return Some(if low.starts_with("https://") { 443 } else { 80 });
        }
    }
    None
}

fn template_key_for(rule: &str, category: &str) -> &'static str {
    match rule {
        "secret" | "rdp-password" | "ica-password" | "recon.js_secret" | "uri-credentials"
        | "git-extraheader" | "env-secret" | "pass" | "doc.links" => "secrets",

        "revisions"
        | "pdf-revisions"
        | "thumbnail"
        | "hidden-sheets"
        | "macros"
        | "pdf-javascript"
        | "doc.bad_redaction"
        | "doc.hidden_content"
        | "doc.pdf_removed_text"
        | "doc.pdf_revision_authors"
        | "doc.lineage"
        | "doc.author_cluster"
        | "doc.ai_generated"
        | "zip.path_traversal" => "doc-sanitize",

        "doc.modified_after_signing"
        | "doc.signature_digest_mismatch"
        | "doc.signer_identity"
        | "doc.signature_tsa_gap" => "doc-signature",

        "pii" | "gps" | "pim.contact_pii" | "doc.geodata" => "pii",

        "infra.tls_legacy_version" | "infra.tls_weak_cipher" => "tls-crypto",

        r if r.starts_with("infra.cert_")
            || r == "infra.tls_no_ocsp_stapling"
            || r == "infra.tls_no_alpn"
            || r == "infra.tls_default_cert" =>
        {
            "tls-cert"
        }

        "recon.web.hsts_missing"
        | "recon.web.cors_reflected"
        | "recon.web.cors_wildcard_credentials"
        | "recon.web.cookie_flags"
        | "recon.web.clickjacking"
        | "recon.web.csp_missing"
        | "recon.web.version_disclosure" => "web-headers",

        "recon.web.trace_enabled" | "recon.web.methods_unsafe_allowed" | "recon.web.webdav" => {
            "web-methods"
        }

        "fuzz-backup"
        | "fuzz-db-backup"
        | "fuzz-git"
        | "fuzz-listing"
        | "recon.bucket_listing"
        | "recon.bucket_missing"
        | "recon.robots_hidden"
        | "recon.sourcemap"
        | "remote-file" => "web-exposure",

        "dangling-cname"
        | "takeover-http"
        | "axfr-open"
        | "infra.dns_wildcard"
        | "infra.dns_resolver_hijack"
        | "infra.nsec_walkable"
        | "infra.ptr_shared_hosting"
        | "infra.ptr_fcrdns_mismatch"
        | "infra.ct_abandoned_subdomain"
        | "mail.internal_relay"
        | "mail.originating_ip"
        | "mail.reply_to_mismatch" => "dns-mail",

        "eol-software"
        | "eol-os"
        | "sw.kev"
        | "recon.outdated_tech"
        | "recon.vuln_js_lib"
        | "ports-outdated"
        | "internetdb-cve" => "sw-cve",

        "ports-exposed"
        | "infra.origin_exposed"
        | "infra.tls_origin_confirmed"
        | "infra.host_role_exposed" => "ports-infra",

        "internal-addresses"
        | "internal-paths"
        | "internal-pcs"
        | "mass-names"
        | "service-accounts"
        | "email-pattern"
        | "doc.data_connection"
        | "doc.pdb_user"
        | "doc.sourcemap"
        | "doc.lnk_host_mac"
        | "doc.lnk_unc_path"
        | "media.device_serial"
        | "net.internal_map"
        | "org.structure"
        | "infra.saas_inventory"
        | "infra.m365_tenant"
        | "infra.m365_federated_adfs" => "internal-recon",

        r if r.starts_with("preset:") || r.starts_with("user:") => match category {
            "secrets" | "creds" => "secrets",
            "pii" => "pii",
            _ => "doc-sanitize",
        },

        _ => match category {
            "tls" => "tls-cert",
            "dns" | "mail" => "dns-mail",
            "ports" | "cloud" | "hosts" => "ports-infra",
            "software" | "cve" => "sw-cve",
            "secrets" => "secrets",
            "pii" => "pii",
            "forensics" | "docs" => "doc-sanitize",
            "web" | "recon" | "fuzz" => "web-headers",
            _ => "general",
        },
    }
}

fn format_references(rule: &str, lang: &str) -> Vec<String> {
    use crate::standards::{
        is_cwe_top25, ATTACK_VERSION, ISO_27001, NDTZI_3_6_006, NIST_800_53, OWASP_TOP10,
    };
    let stds = Standards::builtin();
    let Some(r) = stds.for_rule(rule) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if !r.cwe.is_empty() {
        let cwe: Vec<String> = r
            .cwe
            .iter()
            .map(|c| {
                if is_cwe_top25(c) {
                    format!("{c} (CWE Top 25:2025)")
                } else {
                    c.clone()
                }
            })
            .collect();
        out.push(format!("CWE: {}", cwe.join(", ")));
    }
    if !r.owasp.is_empty() {
        out.push(format!("{OWASP_TOP10}: {}", r.owasp.join(", ")));
    }
    if !r.wstg.is_empty() {
        out.push(format!("OWASP WSTG v4.2: {}", r.wstg.join(", ")));
    }
    if !r.mitre.is_empty() {
        out.push(format!("MITRE {ATTACK_VERSION}: {}", r.mitre.join(", ")));
    }
    if !r.iso27001.is_empty() {
        out.push(format!("{ISO_27001} A.{}", r.iso27001.join(", A.")));
    }
    if !r.nist.is_empty() {
        let ids = r.nist.join(", ");
        out.push(format!("{NIST_800_53}: {ids}"));
        out.push(format!("{NDTZI_3_6_006}: {ids}"));
    }
    for p in &r.privacy {
        if let Some(x) = stds.privacy.get(p) {
            out.push(x.code.clone());
        }
    }
    let legacy = crate::standards::legacy_note(lang);
    if !r.ndtzi.is_empty() {
        out.push(format!(
            "НД ТЗІ 2.5-004-99 ({legacy}): {}",
            r.ndtzi.join(", ")
        ));
    }
    if !r.kszi.is_empty() {
        out.push(format!(
            "НД ТЗІ 3.7-003-05 ({legacy}): {}",
            r.kszi.join(", ")
        ));
    }
    out
}

fn label(map: &BTreeMap<String, String>, code: &str) -> String {
    map.get(code).cloned().unwrap_or_else(|| code.to_string())
}

/// Builds a localized, contextual remediation playbook for `f`.
///
/// `doc_names` should contain human-readable document names corresponding to
/// `f.provenance.docs`. Evidence bytes/strings are never read or interpolated.
pub fn for_finding(f: &Finding, doc_names: &[String], lang: &str) -> Playbook {
    let l = Lang::parse(lang).unwrap_or(Lang::Ru);
    let rule = f.provenance.rule.trim();
    let loc = locale_data(l);
    let key = template_key_for(rule, f.category.trim());
    let tpl = loc
        .playbooks
        .get(key)
        .or_else(|| loc.playbooks.get("general"))
        .expect("general playbook missing from locale");
    let ctx = SafeCtx::from_finding(f, doc_names);
    let steps = tpl
        .steps
        .iter()
        .enumerate()
        .map(|(i, s)| PlaybookStep {
            step: (i + 1) as u8,
            title: ctx.expand(&s.title),
            action: ctx.expand(&s.action),
            command: s.command.as_deref().map(|c| ctx.expand(c)),
            owner: s.owner.clone(),
        })
        .collect();
    let verify = tpl.verify.iter().map(|v| ctx.expand(v)).collect();

    Playbook {
        rule: rule.to_string(),
        playbook_key: tpl.key.clone(),
        key_label: label(&loc.labels.keys, &tpl.key),
        lang: l.code().to_string(),
        title: ctx.expand(&tpl.title),
        summary: ctx.expand(&tpl.summary),
        effort: tpl.effort.clone(),
        effort_label: label(&loc.labels.effort, &tpl.effort),
        steps,
        verify,
        references: format_references(rule, l.code()),
        disclaimer: loc.disclaimer.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::api::FindingProvenance;
    use foca_core::{FindingStatus, Severity};

    fn sample_finding(rule: &str, host: &str, evidence: &str) -> Finding {
        Finding {
            id: 42,
            title: "Test finding".into(),
            sev: Severity::High,
            status: FindingStatus::New,
            host: host.into(),
            category: "misc".into(),
            source: "crawler".into(),
            module: "audit".into(),
            active: false,
            time: "2026-11-20T12:00:00Z".into(),
            first_scan: None,
            fixed_scan: None,
            tags: vec![],
            cve: vec!["CVE-2024-1234".into()],
            cvss: None,
            mitre: "T1552".into(),
            description: "desc".into(),
            recommendation: "fix".into(),
            evidence: evidence.into(),
            request: String::new(),
            url: Some(format!("https://{host}/backup.sql")),
            doc: Some(1),
            notes: vec![],
            photos: vec![],
            rel: Default::default(),
            provenance: FindingProvenance {
                rule: rule.into(),
                docs: vec![1],
                ..Default::default()
            },
        }
    }

    #[test]
    fn playbook_locales_are_in_sync() {
        let en = locale_data(Lang::En);
        let ru = locale_data(Lang::Ru);
        let uk = locale_data(Lang::Uk);
        let en_keys: Vec<_> = en.playbooks.keys().collect();
        let ru_keys: Vec<_> = ru.playbooks.keys().collect();
        let uk_keys: Vec<_> = uk.playbooks.keys().collect();
        assert_eq!(en_keys, ru_keys);
        assert_eq!(en_keys, uk_keys);
        assert!(!en.disclaimer.is_empty());
        assert!(!ru.disclaimer.is_empty());
        assert!(!uk.disclaimer.is_empty());
        for k in &en_keys {
            let pe = &en.playbooks[*k];
            let pr = &ru.playbooks[*k];
            let pu = &uk.playbooks[*k];
            assert_eq!(pe.steps.len(), pr.steps.len(), "steps mismatch for {k}");
            assert_eq!(pe.steps.len(), pu.steps.len(), "steps mismatch for {k}");
            assert_eq!(pe.verify.len(), pr.verify.len(), "verify mismatch for {k}");
            assert_eq!(pe.verify.len(), pu.verify.len(), "verify mismatch for {k}");
        }
        for loc in [en, ru, uk] {
            for (k, p) in &loc.playbooks {
                assert!(loc.labels.keys.contains_key(&p.key), "no label for key {k}");
                assert!(
                    loc.labels.effort.contains_key(&p.effort),
                    "no label for {}",
                    p.effort
                );
                for s in &p.steps {
                    assert!(
                        !s.title.starts_with(|c: char| c.is_ascii_digit()),
                        "numbered step title in {k}: {}",
                        s.title
                    );
                }
            }
        }
    }

    #[test]
    fn every_standard_and_infra_rule_has_non_empty_playbook_in_all_langs() {
        let stds = Standards::builtin();
        for rule in &stds.rules {
            let f = sample_finding(&rule.id, "portal.contoso.ua", "SECRET_SHOULD_NOT_LEAK");
            for lang in ["uk", "ru", "en"] {
                let pb = for_finding(&f, &["report.pdf".into()], lang);
                assert!(!pb.title.is_empty(), "{}: empty title", rule.id);
                assert!(!pb.summary.is_empty(), "{}: empty summary", rule.id);
                assert!(
                    !pb.steps.is_empty() && !pb.verify.is_empty(),
                    "{}: missing steps/verify",
                    rule.id
                );
                assert!(!pb.references.is_empty(), "{}: missing stds ref", rule.id);
                let json = serde_json::to_string(&pb).unwrap();
                assert!(
                    !json.contains("SECRET_SHOULD_NOT_LEAK"),
                    "evidence leaked into playbook for {}",
                    rule.id
                );
            }
        }
        for r in crate::infra::RULES {
            let rid = crate::infra::rule_id(r.code);
            let f = sample_finding(&rid, "vpn.contoso.ua", "TOKEN_ABC_XYZ");
            let pb = for_finding(&f, &[], "uk");
            assert_ne!(pb.playbook_key, "general", "unmapped infra rule {rid}");
            assert!(!pb.steps.is_empty());
        }
    }

    #[test]
    fn context_sanitizes_injection_and_strips_url_userinfo() {
        let mut f = sample_finding(
            "recon.web.hsts_missing",
            "app.contoso.ua;rm -rf /",
            "raw_password_999",
        );
        f.url = Some("https://admin:topsecret@app.contoso.ua:8443/login?q=1;cat".into());
        let pb = for_finding(&f, &[], "en");
        let cmd = pb.steps[0].command.as_deref().unwrap_or("");
        assert!(
            !cmd.contains("topsecret"),
            "userinfo leaked into url: {cmd}"
        );
        assert!(!cmd.contains(';'), "shell metachar leaked into cmd: {cmd}");
        assert!(!cmd.contains("raw_password_999"));
        assert!(cmd.contains("app.contoso.ua:8443"));

        // Shell metacharacters, IPv6, and 2-level public suffix (.gov.ua)
        assert!(
            !sanitize_label("a$(id)\\*?()~!.pdf").contains(['\\', '(', ')', '*', '?', '~', '!'])
        );
        assert_eq!(sanitize_domain("2001:db8::1"), "2001:db8::1");
        assert_eq!(sanitize_domain("portal.city.gov.ua"), "city.gov.ua");
        assert_eq!(sanitize_domain("city.gov.ua"), "city.gov.ua");
    }
}
