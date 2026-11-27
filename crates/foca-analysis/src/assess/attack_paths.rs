//! Attack paths and remediation choke points.
//!
//! Correlates leaked documents and configuration artifacts (`.ovpn`, `.env`, `.rdp`, secrets,
//! LNK/UNC paths), extracted corporate identities / AD login templates, and exposed perimeter
//! hosts or KEV vulnerabilities into ranked attack chains, and identifies high-impact
//! remediation choke points whose fix breaks the greatest number of attack paths at once.
//!
//! Raw secrets and unmasked PII are never interpolated into any label or detail field.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::{Doc, Email, Finding, Host, PathItem, Person, Secret};
use foca_core::Severity;
use serde::{Deserialize, Serialize};

use crate::Analysis;

/// Single step in a directed attack chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackStep {
    /// Step category: `"document" | "credential" | "identity" | "perimeter" | "vulnerability"`.
    pub kind: String,
    pub node_id: String,
    pub label: String,
    pub detail: String,
    pub finding_id: Option<u64>,
    pub doc_id: Option<u64>,
    pub host: Option<String>,
}

/// Ranked compromise path linking leaks to exposed entry points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub score: u8,
    pub likelihood: String,
    pub target_host: String,
    pub steps: Vec<AttackStep>,
    pub finding_ids: Vec<u64>,
    pub doc_ids: Vec<u64>,
}

/// Minimum-cut remediation choke point: fixing this node breaks multiple attack paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChokePoint {
    pub node_id: String,
    pub kind: String,
    pub label: String,
    pub paths_broken: u32,
    pub priority_score: u8,
    pub recommendation: String,
    pub finding_ids: Vec<u64>,
}

/// Aggregate counters for an attack path report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPathSummary {
    pub total_paths: u32,
    pub critical_or_high: u32,
    pub choke_points: u32,
    pub max_score: u8,
}

/// Attack path and choke point analysis result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPathReport {
    pub paths: Vec<AttackPath>,
    pub choke_points: Vec<ChokePoint>,
    pub summary: AttackPathSummary,
}

fn sev_weight(s: Severity) -> u8 {
    match s {
        Severity::Critical => 40,
        Severity::High => 30,
        Severity::Medium => 20,
        Severity::Low => 10,
        Severity::Info => 4,
    }
}

/// Node kind of a leak finding: `credential` (a real secret, token or credential file),
/// `exposure` (personal data, internal names and paths: helps an attacker, grants nothing by
/// itself) or `None` (not a path step).
fn leak_kind(f: &Finding) -> Option<&'static str> {
    let rule = f.provenance.rule.as_str();
    if is_perimeter_or_vuln_finding(rule, f) || rule == "doc.meeting_passcode" {
        return None;
    }
    let credential_tag = f.tags.iter().any(|t| t == "credential");
    let medium_up = matches!(
        f.sev,
        Severity::Critical | Severity::High | Severity::Medium
    );
    match rule {
        // A link is a credential only with a real token parameter (signature, SAS, access
        // token); a public share link is context. Recovered text of a bad redaction is a
        // credential only when the secret scanner found one in it, else data exposure.
        "doc.links" => return credential_tag.then_some("credential"),
        "doc.bad_redaction" => {
            return Some(if credential_tag {
                "credential"
            } else {
                "exposure"
            })
        }
        _ => {}
    }
    if credential_tag
        || rule.contains("secret")
        || rule.contains("password")
        || rule.contains("remote-file")
        || rule.contains("artifact.")
        || (f.module == "secrets" && medium_up)
    {
        Some("credential")
    } else if rule == "internal-paths"
        || rule == "internal-addresses"
        || rule == "internal-pcs"
        || rule.starts_with("lnk.")
        || (matches!(f.module.as_str(), "forensics" | "pii") && medium_up)
    {
        Some("exposure")
    } else {
        None
    }
}

/// Storage providers (Google Drive, OneDrive, SharePoint, Dropbox) host files of the target but
/// are not its hosts: never a node, target or choke point.
fn usable_host(h: &str) -> bool {
    let h = h.trim();
    !h.is_empty() && h != "-" && !crate::util::is_storage_provider(h)
}

/// Path severity: the band of its score (the shared CVSS-style bands), never above its
/// strongest component; the score is clipped into the band of the final severity.
fn path_severity(score: u8, components: &[Severity]) -> (u8, &'static str, &'static str) {
    let band = crate::assess::draft::cvss_band(f32::from(score) / 10.0);
    let top = components
        .iter()
        .copied()
        .max_by_key(|s| s.rank())
        .unwrap_or(Severity::Low);
    let sev = if band.rank() > top.rank() { top } else { band };
    let max = match sev {
        Severity::Critical => 99,
        Severity::High => 89,
        Severity::Medium => 69,
        _ => 39,
    };
    let (name, likelihood) = match sev {
        Severity::Critical => ("critical", "high"),
        Severity::High => ("high", "high"),
        Severity::Medium => ("medium", "medium"),
        _ => ("low", "low"),
    };
    (score.min(max), name, likelihood)
}

fn is_perimeter_or_vuln_finding(rule: &str, f: &Finding) -> bool {
    rule == "sw.kev"
        || rule.starts_with("recon.")
        || rule.starts_with("port.")
        || rule.starts_with("tls.")
        || rule.starts_with("mail.")
        || rule.starts_with("infra.")
        || !f.cve.is_empty()
}

fn host_entry_rank(h: &Host) -> u8 {
    let mut r = 10u8;
    let role_l = h.role.to_ascii_lowercase();
    let name_l = h.name.to_ascii_lowercase();
    if role_l.contains("vpn")
        || role_l.contains("rdp")
        || role_l.contains("mail")
        || name_l.starts_with("vpn")
        || name_l.starts_with("owa")
        || name_l.starts_with("rdp")
        || name_l.starts_with("remote")
        || name_l.starts_with("admin")
    {
        r += 25;
    }
    if !h.services.is_empty() {
        r += 15;
    }
    if !h.internal {
        r += 10;
    }
    r
}

/// Computes top attack paths and remediation choke points directly from an [`Analysis`].
pub fn build_attack_paths(a: &Analysis) -> AttackPathReport {
    build_attack_paths_from_parts(
        &a.findings,
        &a.docs,
        &a.hosts,
        &a.people,
        &a.emails,
        &a.secrets,
        &a.paths,
    )
}

/// Computes attack paths and choke points from explicit entity slices (deterministic, secret-safe).
pub fn build_attack_paths_from_parts(
    findings: &[Finding],
    docs: &[Doc],
    hosts: &[Host],
    people: &[Person],
    emails: &[Email],
    secrets: &[Secret],
    paths_items: &[PathItem],
) -> AttackPathReport {
    let doc_by_id: BTreeMap<u64, &Doc> = docs
        .iter()
        .filter(|d| !d.deleted)
        .map(|d| (d.id, d))
        .collect();

    // 1. Collect source leaks / credentials (findings, masked secrets, RDP/OVPN/ENV docs).
    let mut leak_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            !matches!(
                f.status,
                foca_core::FindingStatus::FalsePositive | foca_core::FindingStatus::Fixed
            ) && leak_kind(f).is_some()
        })
        .collect();
    leak_findings.sort_by(|a, b| {
        sev_weight(b.sev)
            .cmp(&sev_weight(a.sev))
            .then_with(|| a.id.cmp(&b.id))
    });

    // 2. Collect exposed perimeter hosts and high-risk target findings (KEV / recon / ports).
    let mut target_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            !matches!(
                f.status,
                foca_core::FindingStatus::FalsePositive | foca_core::FindingStatus::Fixed
            ) && is_perimeter_or_vuln_finding(&f.provenance.rule, f)
                && usable_host(&f.host)
        })
        .collect();
    target_findings.sort_by(|a, b| {
        sev_weight(b.sev)
            .cmp(&sev_weight(a.sev))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut ranked_hosts: Vec<&Host> = hosts.iter().filter(|h| usable_host(&h.name)).collect();
    ranked_hosts.sort_by(|a, b| {
        host_entry_rank(b)
            .cmp(&host_entry_rank(a))
            .then_with(|| a.name.cmp(&b.name))
    });

    // 3. Collect usable identity anchors (non-service people or path usernames or email logins).
    let identity_anchor: Option<(String, String)> = people
        .iter()
        .find(|p| !p.service && !p.login.trim().is_empty())
        .map(|p| (p.login.clone(), p.name.clone()))
        .or_else(|| {
            emails.iter().find(|e| !e.role).map(|e| {
                (
                    e.login.clone().unwrap_or_else(|| e.addr.clone()),
                    e.addr.clone(),
                )
            })
        })
        .or_else(|| {
            paths_items
                .iter()
                .find_map(|p| p.user.as_ref().map(|u| (u.clone(), p.path.clone())))
        });

    let mut built_paths: Vec<AttackPath> = Vec::new();
    let mut seen_signatures: BTreeSet<String> = BTreeSet::new();

    // Resolves the target host and the optional vulnerability finding.
    let resolve_target = |preferred_host: Option<&str>| -> (String, Option<&Finding>) {
        if let Some(ph) = preferred_host.filter(|h| *h != "-" && !h.is_empty()) {
            let tf = target_findings
                .iter()
                .copied()
                .find(|f| f.host.eq_ignore_ascii_case(ph))
                .or_else(|| target_findings.first().copied());
            return (ph.to_string(), tf);
        }
        if let Some(tf) = target_findings.first().copied() {
            let h = if tf.host != "-" && !tf.host.is_empty() {
                tf.host.clone()
            } else {
                ranked_hosts
                    .first()
                    .map(|h| h.name.clone())
                    .unwrap_or_else(|| "perimeter".into())
            };
            return (h, Some(tf));
        }
        if let Some(h) = ranked_hosts.first() {
            return (h.name.clone(), None);
        }
        ("perimeter".into(), None)
    };

    // Build chains anchored on credential/config/artifact leak findings.
    for (idx, lf) in leak_findings.iter().take(10).enumerate() {
        let doc_id = lf.doc.or_else(|| lf.provenance.docs.first().copied());
        let doc_opt = doc_id.and_then(|id| doc_by_id.get(&id).copied());
        let kind = leak_kind(lf).unwrap_or("exposure");
        let preferred_host = secrets
            .iter()
            .find(|s| s.finding == Some(lf.id))
            .and_then(|s| s.host.as_deref())
            .filter(|h| usable_host(h))
            .or_else(|| doc_opt.and_then(|d| d.rdp.as_ref().map(|r| r.full_address.as_str())))
            .or_else(|| usable_host(&lf.host).then_some(lf.host.as_str()))
            // A file on a storage provider: the site that links it.
            .or_else(|| doc_opt.map(|d| d.host.as_str()).filter(|h| usable_host(h)));

        let (target_host, vuln_opt) = resolve_target(preferred_host);
        if target_host == "perimeter" && vuln_opt.is_none() && ranked_hosts.is_empty() {
            continue;
        }

        let mut steps = Vec::new();
        let mut f_ids = Vec::new();
        let mut d_ids = Vec::new();

        if let Some(doc) = doc_opt {
            d_ids.push(doc.id);
            let host = usable_host(&doc.host).then(|| doc.host.clone());
            steps.push(AttackStep {
                kind: "document".into(),
                node_id: format!("doc:{}", doc.id),
                label: doc.name.clone(),
                detail: match &host {
                    Some(h) => format!("Документ ({}) на хосте {h}", doc.ext),
                    None => format!("Документ ({})", doc.ext),
                },
                finding_id: Some(lf.id),
                doc_id: Some(doc.id),
                host,
            });
        }

        // Credential / leak node (never expose raw secret value)
        f_ids.push(lf.id);
        let cred_detail = secrets
            .iter()
            .find(|s| s.finding == Some(lf.id))
            .map(|s| format!("Тип: {} (значение: {})", s.kind, s.value.masked()))
            .unwrap_or_else(|| lf.title.clone());
        steps.push(AttackStep {
            kind: kind.into(),
            node_id: format!("finding:{}", lf.id),
            label: lf.title.clone(),
            detail: cred_detail,
            finding_id: Some(lf.id),
            doc_id,
            host: Some(target_host.clone()),
        });

        if let Some((login, _name)) = &identity_anchor {
            steps.push(AttackStep {
                kind: "identity".into(),
                node_id: format!("person:{}", login.to_ascii_lowercase()),
                label: format!("Логин/УЗ: {login}"),
                detail: "Корпоративная учётная запись / формат входа".into(),
                finding_id: None,
                doc_id,
                host: None,
            });
        }

        if let Some(vf) = vuln_opt {
            if !f_ids.contains(&vf.id) {
                f_ids.push(vf.id);
            }
            steps.push(AttackStep {
                kind: "vulnerability".into(),
                node_id: format!("host:{}", target_host.to_ascii_lowercase()),
                label: target_host.clone(),
                detail: vf.title.clone(),
                finding_id: Some(vf.id),
                doc_id: None,
                host: Some(target_host.clone()),
            });
        } else {
            steps.push(AttackStep {
                kind: "perimeter".into(),
                node_id: format!("host:{}", target_host.to_ascii_lowercase()),
                label: target_host.clone(),
                detail: "Точка входа внешнего периметра".into(),
                finding_id: None,
                doc_id: None,
                host: Some(target_host.clone()),
            });
        }

        let mut score = sev_weight(lf.sev) + if kind == "credential" { 15 } else { 5 };
        let mut parts = vec![lf.sev];
        if let Some(vf) = vuln_opt {
            score = score.saturating_add(sev_weight(vf.sev) / 2 + 12);
            parts.push(vf.sev);
        }
        if identity_anchor.is_some() {
            score = score.saturating_add(10);
        }
        let (score, severity, likelihood) = path_severity(score.min(99), &parts);

        let sig = format!("{target_host}::{}", lf.provenance.rule);
        if seen_signatures.insert(sig) {
            built_paths.push(AttackPath {
                id: format!("ap-{}", idx + 1),
                title: format!("{} → {}", lf.title, target_host),
                severity: severity.into(),
                score,
                likelihood: likelihood.into(),
                target_host: target_host.clone(),
                steps,
                finding_ids: f_ids,
                doc_ids: d_ids,
            });
        }
    }

    // Fallback chain from pure perimeter KEV/exposed services when no document leak existed.
    if built_paths.is_empty() {
        for (idx, vf) in target_findings.iter().take(3).enumerate() {
            let host_name = if vf.host != "-" && !vf.host.is_empty() {
                vf.host.clone()
            } else {
                ranked_hosts
                    .first()
                    .map(|h| h.name.clone())
                    .unwrap_or_else(|| "perimeter".into())
            };
            let (score, severity, likelihood) =
                path_severity((sev_weight(vf.sev) + 35).min(95), &[vf.sev]);
            built_paths.push(AttackPath {
                id: format!("ap-net-{}", idx + 1),
                title: format!("Прямой вход: {} ({})", host_name, vf.title),
                severity: severity.into(),
                score,
                likelihood: likelihood.into(),
                target_host: host_name.clone(),
                steps: vec![
                    AttackStep {
                        kind: "perimeter".into(),
                        node_id: format!("host:{}", host_name.to_ascii_lowercase()),
                        label: host_name.clone(),
                        detail: "Внешний сервис в области сканирования".into(),
                        finding_id: Some(vf.id),
                        doc_id: None,
                        host: Some(host_name.clone()),
                    },
                    AttackStep {
                        kind: "vulnerability".into(),
                        node_id: format!("finding:{}", vf.id),
                        label: vf.title.clone(),
                        detail: if vf.cve.is_empty() {
                            "Ослабленная конфигурация сервиса".into()
                        } else {
                            format!("CVE: {}", vf.cve.join(", "))
                        },
                        finding_id: Some(vf.id),
                        doc_id: None,
                        host: Some(host_name),
                    },
                ],
                finding_ids: vec![vf.id],
                doc_ids: Vec::new(),
            });
        }
    }

    built_paths.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.steps.len().cmp(&a.steps.len()))
            .then_with(|| a.id.cmp(&b.id))
    });
    built_paths.truncate(5);

    // 4. Compute minimum-cut remediation choke points across the selected paths.
    #[derive(Default)]
    struct NodeAgg {
        kind: String,
        label: String,
        path_idxs: BTreeSet<usize>,
        finding_ids: BTreeSet<u64>,
        max_path_score: u8,
    }
    let mut agg: BTreeMap<String, NodeAgg> = BTreeMap::new();
    for (p_idx, p) in built_paths.iter().enumerate() {
        for s in &p.steps {
            let entry = agg.entry(s.node_id.clone()).or_insert_with(|| NodeAgg {
                kind: s.kind.clone(),
                label: s.label.clone(),
                ..Default::default()
            });
            entry.path_idxs.insert(p_idx);
            entry.max_path_score = entry.max_path_score.max(p.score);
            if let Some(fid) = s.finding_id {
                entry.finding_ids.insert(fid);
            }
        }
    }

    let mut choke_points: Vec<ChokePoint> = agg
        .into_iter()
        .filter(|(_, a)| !a.path_idxs.is_empty() && !a.finding_ids.is_empty())
        .map(|(node_id, a)| {
            let broken = a.path_idxs.len() as u32;
            let prio = a
                .max_path_score
                .saturating_add((broken.min(5) as u8) * 5)
                .min(100);
            let rec = match a.kind.as_str() {
                "credential" => {
                    "Отозвать или сменить учётные данные и убрать файл из открытого доступа."
                }
                "document" => "Убрать документ из открытого доступа и очистить метаданные.",
                "exposure" => {
                    "Удалить или обезличить данные в документе и убрать его из открытого доступа."
                }
                "vulnerability" => {
                    "Установить обновления безопасности на узле и проверить его находки."
                }
                "perimeter" => {
                    "Закрыть лишние сервисы и порты узла по его находкам, усилить фильтрацию на периметре."
                }
                _ => "Ограничить раскрытие учётных имён и проверить права доступа на целевом узле.",
            }
            .to_string();
            ChokePoint {
                node_id,
                kind: a.kind,
                label: a.label,
                paths_broken: broken,
                priority_score: prio,
                recommendation: rec,
                finding_ids: a.finding_ids.into_iter().collect(),
            }
        })
        .collect();

    choke_points.sort_by(|a, b| {
        b.paths_broken
            .cmp(&a.paths_broken)
            .then_with(|| b.priority_score.cmp(&a.priority_score))
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    choke_points.truncate(5);

    let summary = AttackPathSummary {
        total_paths: built_paths.len() as u32,
        critical_or_high: built_paths
            .iter()
            .filter(|p| matches!(p.severity.as_str(), "critical" | "high"))
            .count() as u32,
        choke_points: choke_points.len() as u32,
        max_score: built_paths.iter().map(|p| p.score).max().unwrap_or(0),
    };

    AttackPathReport {
        paths: built_paths,
        choke_points,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::api::{FindingProvenance, FindingRel, SecretValue};
    use foca_core::FindingStatus;

    fn sample_finding(
        id: u64,
        rule: &str,
        title: &str,
        sev: Severity,
        host: &str,
        doc: Option<u64>,
    ) -> Finding {
        Finding {
            id,
            title: title.into(),
            sev,
            status: FindingStatus::default(),
            host: host.into(),
            category: "docs".into(),
            source: "doc".into(),
            module: "secrets".into(),
            active: false,
            time: "2026-11-22T10:00:00".into(),
            first_scan: None,
            fixed_scan: None,
            tags: Vec::new(),
            cve: Vec::new(),
            cvss: None,
            mitre: String::new(),
            description: String::new(),
            recommendation: String::new(),
            evidence: String::new(),
            request: String::new(),
            url: None,
            doc,
            notes: Vec::new(),
            photos: Vec::new(),
            rel: FindingRel::default(),
            provenance: FindingProvenance {
                rule: rule.into(),
                fields: Vec::new(),
                docs: doc.into_iter().collect(),
            },
        }
    }

    #[test]
    fn builds_ranked_paths_and_choke_points_without_leaking_secrets() {
        let docs = vec![Doc {
            id: 1,
            ext: "ovpn".into(),
            name: "corp-vpn.ovpn".into(),
            host: "vpn.corp.test".into(),
            ..Default::default()
        }];
        let hosts = vec![Host {
            name: "vpn.corp.test".into(),
            ip: "198.51.100.10".into(),
            role: "vpn".into(),
            services: vec![("1194".into(), "openvpn".into(), "".into())],
            ..Default::default()
        }];
        let people = vec![Person {
            login: "i.petrenko".into(),
            name: "Іван Петренко".into(),
            ..Default::default()
        }];
        let raw_secret = "SuperSecretToken_99999!";
        let secrets = vec![Secret {
            id: 10,
            kind: "pass".into(),
            value: SecretValue::new(raw_secret),
            doc: 1,
            location: "body".into(),
            sev: Severity::Critical,
            host: Some("vpn.corp.test".into()),
            finding: Some(101),
            rule: "secret".into(),
        }];
        let mut f_vuln = sample_finding(
            202,
            "sw.kev",
            "CISA KEV CVE-2024-38077 на vpn.corp.test",
            Severity::High,
            "vpn.corp.test",
            None,
        );
        f_vuln.cve = vec!["CVE-2024-38077".into()];
        let findings = vec![
            sample_finding(
                101,
                "artifact.ovpn",
                "Утечка VPN-конфигурации и пароля",
                Severity::Critical,
                "vpn.corp.test",
                Some(1),
            ),
            f_vuln,
        ];

        let report =
            build_attack_paths_from_parts(&findings, &docs, &hosts, &people, &[], &secrets, &[]);
        assert_eq!(report.paths.len(), 1);
        assert!(report.paths[0].score >= 85);
        assert_eq!(report.paths[0].severity, "critical");
        assert!(report.paths[0].steps.len() >= 3);
        assert!(!report.choke_points.is_empty());

        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(raw_secret));
    }

    fn host(name: &str) -> Host {
        Host {
            name: name.into(),
            services: vec![("443".into(), "https".into(), "".into())],
            ..Default::default()
        }
    }

    #[test]
    fn storage_providers_public_links_and_pii_are_classified() {
        let docs = vec![Doc {
            id: 1,
            ext: "pdf".into(),
            name: "order.pdf".into(),
            host: "www.example.com".into(),
            ..Default::default()
        }];
        let hosts = vec![host("drive.google.com"), host("www.example.com")];
        // a public share link (no token): not a credential, no path at all
        let mut link = sample_finding(
            1,
            "doc.links",
            "Links",
            Severity::Info,
            "drive.google.com",
            Some(1),
        );
        link.module = "forensics".into();
        // a SAS link with a real token: credential node, target is the linking site
        let mut sas = sample_finding(
            2,
            "doc.links",
            "SAS",
            Severity::High,
            "drive.google.com",
            Some(1),
        );
        sas.module = "forensics".into();
        sas.tags = vec!["credential".into()];
        // bad redaction with personal data only: data exposure node
        let mut red = sample_finding(
            3,
            "doc.bad_redaction",
            "Redaction",
            Severity::Critical,
            "www.example.com",
            Some(1),
        );
        red.module = "forensics".into();
        let rep =
            build_attack_paths_from_parts(&[link, sas, red], &docs, &hosts, &[], &[], &[], &[]);
        let kinds: Vec<(u64, &str)> = rep
            .paths
            .iter()
            .flat_map(|p| p.steps.iter())
            .filter_map(|s| s.finding_id.map(|f| (f, s.kind.as_str())))
            .filter(|(_, k)| *k != "document")
            .collect();
        assert!(kinds.contains(&(2, "credential")), "{kinds:?}");
        assert!(kinds.contains(&(3, "exposure")), "{kinds:?}");
        assert!(!kinds.iter().any(|(f, _)| *f == 1), "{kinds:?}");
        let json = serde_json::to_string(&rep).unwrap();
        assert!(!json.contains("drive.google.com"), "{json}");
        assert!(rep.paths.iter().all(|p| p.target_host == "www.example.com"));
        // severity never above the strongest component, score inside its band
        for p in &rep.paths {
            let comp: Vec<Severity> = p
                .finding_ids
                .iter()
                .map(|id| {
                    if *id == 2 {
                        Severity::High
                    } else {
                        Severity::Critical
                    }
                })
                .collect();
            assert!(!(p.severity == "critical" && !comp.contains(&Severity::Critical)));
            assert!(p.severity != "high" || p.score < 90, "{}", p.score);
        }
        let cp = rep
            .choke_points
            .iter()
            .find(|c| c.kind == "document")
            .unwrap();
        assert!(cp.recommendation.starts_with("Убрать документ"));
    }

    #[test]
    fn empty_project_returns_empty_attack_paths_cleanly() {
        let rep = build_attack_paths(&Analysis::default());
        assert!(rep.paths.is_empty());
        assert!(rep.choke_points.is_empty());
        assert_eq!(rep.summary.total_paths, 0);
    }

    #[test]
    fn fixed_and_false_positive_findings_excluded_from_attack_paths() {
        let mut f1 = sample_finding(
            1,
            "artifact.ovpn",
            "Leak",
            Severity::Critical,
            "vpn.corp.test",
            Some(1),
        );
        f1.status = foca_core::FindingStatus::FalsePositive;
        let mut f2 = sample_finding(2, "sw.kev", "KEV", Severity::High, "vpn.corp.test", None);
        f2.status = foca_core::FindingStatus::Fixed;
        let rep = build_attack_paths_from_parts(&[f1, f2], &[], &[], &[], &[], &[], &[]);
        assert!(rep.paths.is_empty());
    }
}
