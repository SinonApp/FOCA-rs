//! Analytics in the engine: `foca_analysis::insights` over the project documents and
//! the PKI hints, the findings derived from it (metadata anomalies, CISA KEV matches,
//! document lineage, org chart, internal network map), the org chart fields of people, the
//! `insights_get` / `chain_get` views and the report diagrams (`foca_report::Visuals`).
//!
//! Everything is recomputed from stored data (pure functions, milliseconds for hundreds of
//! documents), so nothing new is persisted and old projects need no migration.

use std::collections::{BTreeMap, BTreeSet};

use foca_analysis::attack_paths::{self, AttackPathReport};
use foca_analysis::chain::{self, ChainOpts};
use foca_analysis::findings::{finding_id, ru_n};
use foca_analysis::graphview::{self, Layer};
use foca_analysis::insights::{self, Insights};
use foca_analysis::netmap::{NetKind, PkiInput};
use foca_analysis::{analyze, Analysis, DocInput, PrevState};
use foca_core::api::{self, FindingProvenance, FindingRel};
use foca_core::{FindingStatus, Severity};
use foca_store::ProjectDb;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::analysis::facts::{self, NetFacts};
use crate::CmdError;

/// Rule ids of the findings.
pub const RULE_ANOMALY: &str = "doc.anomaly";
pub const RULE_KEV: &str = "sw.kev";
pub const RULE_LINEAGE: &str = "doc.lineage";
pub const RULE_ORG: &str = "org.structure";
pub const RULE_NETMAP: &str = "net.internal_map";

/// Minimum anomaly confidence that becomes a finding (weaker ones stay in `insights_get`).
const ANOMALY_MIN_CONFIDENCE: u8 = 50;

/// CDP/AIA hints collected by the TLS audit (`infra` records of kind `cert`).
pub fn pki_inputs(db: &ProjectDb) -> Vec<PkiInput> {
    let mut out: Vec<PkiInput> = Vec::new();
    for (_, rec) in db.infra_list("cert").unwrap_or_default() {
        for h in rec["pki"].as_array().into_iter().flatten() {
            if let Ok(p) = serde_json::from_value::<PkiInput>(h.clone()) {
                if !p.url.is_empty() && !out.contains(&p) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// Analysis of the stored documents with network facts merged, plus the insights.
pub struct Computed {
    pub analysis: Analysis,
    pub insights: Insights,
    /// CT history records (`infra` kind `ct`) for the chronology.
    pub ct: Vec<(String, Value)>,
    /// Stored findings from the project DB (used by `attack_paths` alongside `analysis`).
    pub stored_findings: Vec<api::Finding>,
}

/// Merges secret rules from an installed signature bundle into `prev.rules`.
pub(crate) fn apply_bundle_rules(db: &ProjectDb, prev: &mut PrevState) {
    let Some(dir) = db.path().parent() else {
        return;
    };
    let Ok(cfg) = db.rules_config() else {
        return;
    };
    let merged = crate::services::sigbundle::merge_rules_with_bundle(dir, cfg);
    if !merged.rules.is_empty() || !merged.presets.is_empty() {
        if let Ok(rs) = foca_analysis::rules::RuleSet::compile(&merged) {
            if !rs.is_empty() {
                prev.rules = Some(rs);
            }
        }
    }
}

/// Runs insights, extending CISA KEV with any active signed bundle entries.
pub(crate) fn build_insights(
    db: &ProjectDb,
    inputs: &[DocInput],
    a: &Analysis,
    now: OffsetDateTime,
) -> Insights {
    let pki = pki_inputs(db);
    if let Some(cat) = db
        .path()
        .parent()
        .and_then(crate::services::sigbundle::active_kev_catalog)
    {
        insights::build_with_kev(inputs, a, &pki, now, &cat)
    } else {
        insights::build(inputs, a, &pki, now)
    }
}

/// Recomputes the analysis and the insights from the project (read only).
pub fn compute(db: &ProjectDb, now: OffsetDateTime) -> Result<Computed, CmdError> {
    let docs = db.documents(true)?;
    let mut prev = db.prev_state(None)?;
    apply_bundle_rules(db, &mut prev);
    prev.now = prev.now.or(Some(now));
    let inputs = doc_inputs(&docs);
    let mut a = analyze(&inputs, &db.core_scope()?, &prev);
    let nf: NetFacts = facts::get(db, facts::K_NET);
    facts::merge_facts(&mut a, &nf, None, &prev);
    let ins = build_insights(db, &inputs, &a, now);
    let stored_findings = db.findings().unwrap_or_default();
    Ok(Computed {
        analysis: a,
        insights: ins,
        ct: db.infra_list("ct").unwrap_or_default(),
        stored_findings,
    })
}

/// Analyzes the project documents, merges network facts and stores the result with triage
/// preserved. Returns the ids of findings that did not exist before (for `finding` events).
pub fn reanalyze(db: &ProjectDb, scan_id: Option<&str>) -> Result<Vec<u64>, CmdError> {
    let docs = db.documents(true)?;
    let mut prev = db.prev_state(scan_id)?;
    apply_bundle_rules(db, &mut prev);
    let known: BTreeSet<u64> = prev.findings.keys().copied().collect();
    let inputs = doc_inputs(&docs);
    let mut a: Analysis = analyze(&inputs, &db.core_scope()?, &prev);
    let nf: NetFacts = facts::get(db, facts::K_NET);
    facts::merge_facts(&mut a, &nf, scan_id, &prev);
    // Analytics: lineage, org chart, anomalies, KEV, internal network map.
    let now = prev.now.unwrap_or_else(time::OffsetDateTime::now_utc);
    let ins = build_insights(db, &inputs, &a, now);
    apply(&mut a, &ins, &prev, &crate::util::iso(now));
    db.apply_analysis(&a, scan_id)?;
    facts::assign_fids(db)?;
    Ok(a.findings
        .iter()
        .map(|f| f.id)
        .filter(|id| !known.contains(id))
        .collect())
}

pub fn doc_inputs(docs: &[foca_store::project::StoredDoc]) -> Vec<DocInput<'_>> {
    docs.iter()
        .map(|d| DocInput {
            doc: &d.doc,
            text: d.text.as_deref(),
            first_scan: d.first_scan.as_deref(),
            deleted: d.deleted,
            thumb_diff: None,
        })
        .collect()
}

/// Adds the insight findings and the people's org chart fields to an analysis before it is
/// stored. Triage of earlier runs (status, severity override, notes, first scan) is kept.
pub fn apply(a: &mut Analysis, ins: &Insights, prev: &PrevState, now: &str) {
    for p in &mut a.people {
        p.dept = None;
        p.dept_conf = None;
        p.title = None;
        if let Some(o) = ins.org.people.iter().find(|o| o.login == p.login) {
            p.title = o.title.clone();
            if let Some(d) = o
                .department
                .as_ref()
                .and_then(|id| ins.org.departments.iter().find(|d| &d.id == id))
            {
                p.dept = Some(if d.key == "share" {
                    d.labels.first().cloned().unwrap_or_else(|| d.key.clone())
                } else {
                    d.key.clone()
                });
                p.dept_conf = Some(o.dept_confidence);
            }
        }
    }
    for mut f in findings(a, ins, now, prev.scan_id.as_deref()) {
        if let Some(p) = prev.findings.get(&f.id) {
            f.status = match p.status {
                FindingStatus::Fixed => FindingStatus::New,
                s => s,
            };
            if let Some(s) = p.sev {
                f.sev = s;
            }
            f.notes = p.notes.clone();
            f.photos = p.photos.clone();
            for t in &p.tags {
                if !f.tags.contains(t) {
                    f.tags.push(t.clone());
                }
            }
            if p.first_scan.is_some() {
                f.first_scan = p.first_scan.clone();
            }
            if let Some(t) = &p.time {
                f.time = t.clone();
            }
        }
        a.resolved.retain(|id| *id != f.id);
        if !a.findings.iter().any(|x| x.id == f.id) {
            a.findings.push(f);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finding(
    rule: &str,
    key: &str,
    title: String,
    sev: Severity,
    category: &str,
    mitre: &str,
    description: String,
    recommendation: &str,
    evidence: String,
    docs: Vec<u64>,
    now: &str,
    scan: Option<&str>,
) -> api::Finding {
    api::Finding {
        id: finding_id(rule, key),
        title,
        sev,
        status: FindingStatus::New,
        host: "-".into(),
        category: category.into(),
        source: "Аналитика".into(),
        module: "analysis".into(),
        active: false,
        time: now.to_string(),
        first_scan: scan.map(str::to_string),
        fixed_scan: None,
        tags: vec![],
        cve: vec![],
        cvss: None,
        mitre: mitre.into(),
        description,
        recommendation: recommendation.into(),
        evidence,
        request: String::new(),
        url: None,
        doc: docs.first().copied(),
        notes: vec![],
        photos: vec![],
        rel: FindingRel {
            people: vec![],
            pcs: vec![],
            docs: docs.clone(),
        },
        provenance: FindingProvenance {
            rule: rule.into(),
            fields: vec![],
            docs,
        },
    }
}

/// Findings derived from the insights (Russian texts; the report translates them by rule).
pub fn findings(a: &Analysis, ins: &Insights, now: &str, scan: Option<&str>) -> Vec<api::Finding> {
    let facts: BTreeMap<u64, &foca_analysis::DocFacts> =
        a.facts.iter().map(|d| (d.id, d)).collect();
    let name = |id: u64| {
        facts
            .get(&id)
            .map(|d| d.name.clone())
            .unwrap_or_else(|| format!("#{id}"))
    };
    let doc_key = |id: u64| {
        facts
            .get(&id)
            .map(|d| d.key.clone())
            .unwrap_or_else(|| id.to_string())
    };
    let doc_host = |id: u64| {
        facts
            .get(&id)
            .map(|d| d.host.clone())
            .filter(|h| !h.is_empty())
    };
    let doc_url = |id: u64| facts.get(&id).and_then(|d| d.url.clone());
    let mut out = Vec::new();

    // Metadata anomalies: one finding per document and code.
    for an in ins
        .anomalies
        .iter()
        .filter(|x| x.confidence >= ANOMALY_MIN_CONFIDENCE)
    {
        let rule = format!("{RULE_ANOMALY}.{}", an.code);
        let mut f = finding(
            &rule,
            &format!("{}|{}", doc_key(an.doc), an.code),
            format!("{}: «{}»", an.title, name(an.doc)),
            an.sev,
            "docs",
            "",
            an.detail.clone(),
            "Проверить происхождение документа: даты и история правок противоречат друг другу. Сверить с оригиналом и журналами документооборота.",
            format!("Поля: {}\nУверенность: {}%", an.fields.join(", "), an.confidence),
            vec![an.doc],
            now,
            scan,
        );
        f.tags = vec!["forensics".into()];
        f.provenance.fields = an.fields.clone();
        if let Some(h) = doc_host(an.doc) {
            f.host = h;
        }
        f.url = doc_url(an.doc);
        out.push(f);
    }

    // CISA KEV: deduplicate by (product_key, version/probe, subject_kind) so different
    // technologies on the same host never collide while identical tech across multiple hosts
    // merges into one finding with attributed hosts.
    #[derive(Clone)]
    struct KevGroup<'a> {
        product_label: &'a str,
        probe: String,
        kind: foca_analysis::kev::SubjectKind,
        sev: Severity,
        confidence: String,
        total: u32,
        ransomware: u32,
        after_eol: u32,
        eol: bool,
        eol_date: Option<String>,
        hosts: BTreeSet<String>,
        docs: BTreeSet<u64>,
        cves: Vec<foca_analysis::kev::KevRef>,
    }
    let mut kev_groups: BTreeMap<(String, String, u8), KevGroup> = BTreeMap::new();
    let mut kev_order: Vec<(String, String, u8)> = Vec::new();
    for k in &ins.kev {
        let probe = if k.subject.ver.is_empty() {
            k.subject.name.clone()
        } else {
            format!("{} {}", k.subject.name, k.subject.ver)
        };
        let kind_ord = match k.subject.kind {
            foca_analysis::kev::SubjectKind::Tech => 1,
            _ => 0,
        };
        let gkey = (k.product_key.clone(), probe.to_ascii_lowercase(), kind_ord);
        let subj_docs: Vec<u64> = a
            .facts
            .iter()
            .filter(|f| {
                f.software.contains(&k.subject.id) || f.os.as_deref() == Some(&k.subject.id)
            })
            .map(|f| f.id)
            .take(50)
            .collect();
        let entry = kev_groups.entry(gkey.clone()).or_insert_with(|| {
            kev_order.push(gkey);
            KevGroup {
                product_label: &k.product_label,
                probe: probe.clone(),
                kind: k.subject.kind,
                sev: k.sev,
                confidence: k.confidence.clone(),
                total: k.total,
                ransomware: k.ransomware,
                after_eol: k.after_eol,
                eol: k.subject.eol,
                eol_date: k.subject.eol_date.clone(),
                hosts: BTreeSet::new(),
                docs: BTreeSet::new(),
                cves: k.cves.clone(),
            }
        });
        if k.sev.rank() > entry.sev.rank() {
            entry.sev = k.sev;
        }
        if k.confidence == "likely" {
            entry.confidence = "likely".into();
        }
        entry.total = entry.total.max(k.total);
        entry.ransomware = entry.ransomware.max(k.ransomware);
        entry.after_eol = entry.after_eol.max(k.after_eol);
        entry.eol |= k.subject.eol;
        if entry.eol_date.is_none() {
            entry.eol_date = k.subject.eol_date.clone();
        }
        if k.subject.kind == foca_analysis::kev::SubjectKind::Tech {
            let h = k.subject.id.trim();
            if !h.is_empty() && h != "-" {
                entry.hosts.insert(h.to_string());
            }
        } else {
            for did in &subj_docs {
                if let Some(h) = doc_host(*did) {
                    entry.hosts.insert(h);
                }
            }
        }
        entry.docs.extend(subj_docs);
        for c in &k.cves {
            if !entry.cves.iter().any(|x| x.cve == c.cve) {
                entry.cves.push(c.clone());
            }
        }
    }

    for gkey in kev_order {
        let Some(g) = kev_groups.get(&gkey) else {
            continue;
        };
        let likely = g.confidence == "likely";
        let title = if likely {
            format!("Вероятно уязвимое ПО (CISA KEV): {}", g.probe)
        } else {
            format!(
                "Возможно уязвимое ПО (CISA KEV): {}, сверьте версию",
                g.probe
            )
        };
        let mut d = vec![
            match g.kind {
                foca_analysis::kev::SubjectKind::Tech => {
                    "Технология обнаружена на хосте организации.".to_string()
                }
                _ => "ПО найдено в метаданных документов: оно стоит на рабочих станциях авторов."
                    .to_string(),
            },
            format!(
                "Эксплуатируемых уязвимостей в каталоге CISA KEV для продукта «{}»: {}.",
                g.product_label, g.total
            ),
        ];
        if !g.hosts.is_empty() {
            let shown_hosts: Vec<String> = g.hosts.iter().take(20).cloned().collect();
            let extra_h = g.hosts.len().saturating_sub(shown_hosts.len());
            let suffix = if extra_h > 0 {
                format!(" … и ещё {extra_h}")
            } else {
                String::new()
            };
            d.push(format!(
                "Затронутые хосты ({}): {}{suffix}.",
                g.hosts.len(),
                shown_hosts.join(", ")
            ));
        }
        if g.ransomware > 0 {
            d.push(format!("Из них в кампаниях вымогателей: {}.", g.ransomware));
        }
        if g.eol {
            d.push(match &g.eol_date {
                Some(x) => {
                    format!("Версия снята с поддержки ({x}): исправления больше не выходят.")
                }
                None => "Версия снята с поддержки: исправления больше не выходят.".into(),
            });
            if g.after_eol > 0 {
                d.push(format!(
                    "Добавлено в KEV после окончания поддержки: {}.",
                    g.after_eol
                ));
            }
        }
        // FIRST EPSS and CISA Vulnrichment CVSS: the highest values among the matched CVEs.
        let max_of = |f: fn(&foca_analysis::kev::KevEnrich) -> Option<f32>| {
            g.cves
                .iter()
                .filter_map(|c| c.enrich.as_ref().and_then(f))
                .fold(None, |m: Option<f32>, v| Some(m.map_or(v, |m| m.max(v))))
        };
        if let Some(epss) = max_of(|e| e.epss) {
            let cvss = max_of(|e| e.cvss).map_or_else(|| "-".to_string(), |c| c.to_string());
            d.push(format!(
                "Приоритет по EPSS (FIRST): наибольшая вероятность эксплуатации {epss:.2}, CVSS до {cvss}."
            ));
        }
        d.push(format!(
            "Если патч-уровень ОС/дистрибутива не определён автоматически, сверьте версию {} с бюллетенями производителя.",
            g.probe
        ));
        let mut ev_lines: Vec<String> = g
            .cves
            .iter()
            .take(25)
            .map(|c| {
                let extra = c
                    .enrich
                    .as_ref()
                    .map(|e| e.label())
                    .filter(|l| !l.is_empty())
                    .map(|l| format!(" {l}"))
                    .unwrap_or_default();
                format!(
                    "{} ({}){}{extra}",
                    c.cve,
                    c.date_added,
                    if c.ransomware { " ransomware" } else { "" }
                )
            })
            .collect();
        let total_cves = (g.total as usize).max(g.cves.len());
        if total_cves > ev_lines.len() {
            ev_lines.push(format!("… и ещё {}", total_cves - ev_lines.len()));
        }
        let evidence = ev_lines.join("\n");
        let docs: Vec<u64> = g.docs.iter().copied().take(50).collect();
        let id_key = format!("{}|{}|{}", gkey.0, gkey.1, gkey.2);
        let mut f = finding(
            RULE_KEV,
            &id_key,
            title,
            g.sev,
            "software",
            if g.kind == foca_analysis::kev::SubjectKind::Tech {
                "T1190"
            } else {
                "T1203"
            },
            d.join("\n"),
            "Сверить установленную версию с бюллетенями производителя; обновить или вывести ПО из эксплуатации. Каталог KEV не содержит диапазонов версий, поэтому совпадение: повод для проверки, а не подтверждённая уязвимость.",
            evidence,
            docs,
            now,
            scan,
        );
        if !g.hosts.is_empty() {
            let first = g.hosts.iter().next().unwrap();
            f.host = if g.hosts.len() == 1 {
                first.clone()
            } else {
                format!("{first} (+{})", g.hosts.len() - 1)
            };
        }
        f.cve = g.cves.iter().take(25).map(|c| c.cve.clone()).collect();
        f.tags = vec!["kev".into(), g.confidence.clone()];
        if g.eol {
            f.tags.push("eol".into());
        }
        out.push(f);
    }

    // Document lineage: copies and versions of one document.
    for l in ins
        .correlation
        .lineages
        .iter()
        .filter(|l| l.docs.len() >= 2)
    {
        let authors: BTreeSet<String> = l
            .docs
            .iter()
            .filter_map(|d| facts.get(d).and_then(|x| x.author.clone()))
            .map(|s| s.to_lowercase())
            .collect();
        let many = authors.len() > 1;
        let mut desc = format!(
            "Документы связаны общими идентификаторами (XMP DocumentID/DerivedFrom, RSID): {}.",
            ru_n(l.docs.len(), "версия", "версии", "версий")
        );
        if many {
            desc.push_str(&format!(
                "\nАвторы копий различаются ({}): документ пересылали и правили разные люди или организации.",
                authors.len()
            ));
        }
        let mut f = finding(
            RULE_LINEAGE,
            &l.id,
            format!(
                "Копии одного документа: {} («{}»)",
                ru_n(l.docs.len(), "файл", "файла", "файлов"),
                name(l.root)
            ),
            if many { Severity::Low } else { Severity::Info },
            "docs",
            "",
            desc,
            "Сверить версии документа: устаревшие копии могут содержать данные, удалённые из актуальной версии.",
            format!(
                "Основание: {}\nУверенность: {}%\nДокументы: {}",
                l.basis.join(", "),
                l.confidence,
                l.docs.iter().map(|d| name(*d)).collect::<Vec<_>>().join(", ")
            ),
            l.docs.clone(),
            now,
            scan,
        );
        f.tags = vec!["forensics".into()];
        out.push(f);
    }

    // Org chart (social engineering, MITRE T1591.004).
    let depts = ins
        .org
        .departments
        .iter()
        .filter(|d| !d.members.is_empty())
        .count();
    let staff = ins
        .org
        .people
        .iter()
        .filter(|p| p.department.is_some())
        .count();
    if depts > 0 && staff > 0 {
        let docs: Vec<u64> = ins
            .org
            .departments
            .iter()
            .flat_map(|d| d.docs.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(50)
            .collect();
        let list = ins
            .org
            .departments
            .iter()
            .filter(|d| !d.members.is_empty())
            .map(|d| {
                format!(
                    "{}: {}",
                    if d.key == "share" {
                        d.labels.first().cloned().unwrap_or_default()
                    } else {
                        d.key.clone()
                    },
                    d.members.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        out.push(finding(
            RULE_ORG,
            "org",
            format!(
                "Из документов восстановлена оргструктура: {}, {}",
                ru_n(depts, "отдел", "отдела", "отделов"),
                ru_n(staff, "сотрудник", "сотрудника", "сотрудников")
            ),
            Severity::Info,
            "people",
            "T1591.004",
            "Пути к сетевым папкам, принтеры и поля сертификатов связывают сотрудников с отделами. Такая структура помогает подготовить целевой фишинг и социальную инженерию.".into(),
            "Удалять пути, имена принтеров и внутренние поля из публикуемых документов (очистка метаданных перед публикацией).",
            list,
            docs,
            now,
            scan,
        ));
    }

    // Internal network map.
    let servers = ins.netmap.of_kind(NetKind::Server).count();
    let domain = ins
        .netmap
        .of_kind(NetKind::Domain)
        .find(|d| d.id != "domain:unknown")
        .map(|d| d.label.clone());
    if servers > 0 || domain.is_some() {
        let docs: Vec<u64> = ins
            .netmap
            .nodes
            .iter()
            .flat_map(|n| n.docs.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(50)
            .collect();
        let title = match &domain {
            Some(d) => format!(
                "Раскрыта внутренняя инфраструктура: {}, домен {d}",
                ru_n(servers, "сервер", "сервера", "серверов")
            ),
            None => format!(
                "Раскрыта внутренняя инфраструктура: {}",
                ru_n(servers, "сервер", "сервера", "серверов")
            ),
        };
        let ws = ins.netmap.of_kind(NetKind::Workstation).count();
        let evidence = ins
            .netmap
            .of_kind(NetKind::Server)
            .take(30)
            .map(|n| {
                if n.roles.is_empty() {
                    n.label.clone()
                } else {
                    format!("{} [{}]", n.label, n.roles.join(","))
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        out.push(finding(
            RULE_NETMAP,
            "netmap",
            title,
            if servers > 0 && domain.is_some() {
                Severity::Low
            } else {
                Severity::Info
            },
            "hosts",
            "T1590",
            format!(
                "Пути UNC, принтеры, ярлыки, заголовки писем и адреса CDP/AIA сертификатов раскрывают внутреннюю сеть (серверов: {servers}, рабочих станций: {ws})."
            ),
            "Удалять внутренние пути и имена серверов из публикуемых документов; не публиковать внутренние адреса CDP/AIA в публичных сертификатах.",
            evidence,
            docs,
            now,
            scan,
        ));
    }
    out
}

// ---------------------------------------------------------------- views

fn parse_layers(a: &Value) -> Vec<Layer> {
    match a.get("layers").and_then(Value::as_array) {
        Some(v) => v
            .iter()
            .filter_map(|x| serde_json::from_value::<Layer>(x.clone()).ok())
            .collect(),
        None => Layer::ALL
            .iter()
            .copied()
            .filter(|l| *l != Layer::Software)
            .collect(),
    }
}

/// `insights_get` view.
pub fn view(c: &Computed, args: &Value) -> Value {
    let layers = parse_layers(args);
    let min_group = args
        .get("min_group")
        .and_then(Value::as_u64)
        .map_or(graphview::MIN_GROUP, |n| n.clamp(2, 1000) as usize);
    let g = graphview::view(&c.insights.graph, &layers, min_group);
    let ins = &c.insights;
    let timeline: Vec<Value> = timeline_events(c)
        .into_iter()
        .map(|(lane, year, label)| json!({ "lane": lane, "year": year, "label": label }))
        .collect();
    let ap = attack_paths_report(c);
    json!({
        "org": ins.org,
        "correlation": ins.correlation,
        "anomalies": ins.anomalies,
        "kev": ins.kev,
        "netmap": ins.netmap,
        "graph": g,
        "layers": layers.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
        "timeline": timeline,
        "activity": c.analysis.activity,
        "attack_paths": ap,
        "counts": {
            "departments": ins.org.departments.len(),
            "people": ins.org.people.len(),
            "lineages": ins.correlation.lineages.len(),
            "links": ins.correlation.links.len(),
            "anomalies": ins.anomalies.len(),
            "kev": ins.kev.len(),
            "net_nodes": ins.netmap.nodes.len(),
            "graph_nodes": ins.graph.nodes.len(),
        },
    })
}

/// Computes `AttackPathReport` merging persisted DB findings with analyzed documents/hosts.
pub fn attack_paths_report(c: &Computed) -> AttackPathReport {
    let a = &c.analysis;
    if c.stored_findings.is_empty() {
        attack_paths::build_attack_paths(a)
    } else {
        let mut combined = c.stored_findings.clone();
        let existing: BTreeSet<u64> = combined.iter().map(|f| f.id).collect();
        for f in &a.findings {
            if !existing.contains(&f.id) {
                combined.push(f.clone());
            }
        }
        attack_paths::build_attack_paths_from_parts(
            &combined, &a.docs, &a.hosts, &a.people, &a.emails, &a.secrets, &a.paths,
        )
    }
}

/// `chain_get`: shortest readable paths from a start node to infrastructure.
pub fn chains(c: &Computed, start: &str, limit: usize) -> Value {
    let g = &c.insights.graph;
    let start = g
        .nodes
        .iter()
        .find(|n| n.id.eq_ignore_ascii_case(start))
        .map(|n| n.id.clone())
        .unwrap_or_else(|| start.to_string());
    let list = chain::all(g, &start, &ChainOpts::default(), limit.clamp(1, 10));
    json!({ "start": start, "found": g.nodes.iter().any(|n| n.id == start), "chains": list })
}

// ---------------------------------------------------------------- report diagrams

fn year_of(s: &str) -> Option<i32> {
    s.get(..4).and_then(|y| y.parse().ok())
}

/// Chronology events by year: `(lane, year, label)` with lanes `documents` (labelled by
/// format), `software` (last save in the program) and `certificates` (first CT appearance).
pub fn timeline_events(c: &Computed) -> Vec<(&'static str, i32, String)> {
    let a = &c.analysis;
    let mut out = Vec::new();
    let sw: BTreeMap<&str, &str> = a
        .software
        .iter()
        .map(|s| (s.id.as_str(), s.name.as_str()))
        .collect();
    for d in a.facts.iter().filter(|d| d.analyzed) {
        if let Some(y) = d.created.as_deref().and_then(year_of) {
            let ext = d
                .name
                .rsplit_once('.')
                .map(|(_, e)| e.to_uppercase())
                .unwrap_or_else(|| "?".into());
            out.push(("documents", y, ext));
        }
        if let Some(y) = d
            .modified
            .as_deref()
            .or(d.created.as_deref())
            .and_then(year_of)
        {
            for s in &d.software {
                if let Some(n) = sw.get(s.as_str()) {
                    out.push(("software", y, n.to_string()));
                }
            }
        }
    }
    for (_, rec) in &c.ct {
        for h in rec["timeline"].as_array().into_iter().flatten() {
            let (Some(ts), Some(host)) = (h["first_seen"].as_i64(), h["host"].as_str()) else {
                continue;
            };
            if let Ok(t) = OffsetDateTime::from_unix_timestamp(ts) {
                out.push(("certificates", t.year(), host.to_string()));
            }
        }
    }
    out
}

/// Converts the analysis and insights into the report diagrams. `crit` lists findings whose
/// documents and hosts are highlighted.
#[cfg(feature = "report")]
pub fn visuals(c: &Computed, crit: &[api::Finding]) -> foca_report::Visuals {
    use foca_report::svg::NetKind as RK;
    use foca_report::svg::{
        Graph, GraphEdge, GraphNode, Heatmap, Lane, NetMap, NetNode, NodeKind, ServerRole,
        Timeline, TimelineEvent,
    };
    let a = &c.analysis;
    let ins = &c.insights;
    let mut hot: BTreeSet<String> = BTreeSet::new();
    for f in crit
        .iter()
        .filter(|f| matches!(f.sev, Severity::Critical | Severity::High))
    {
        for d in &f.rel.docs {
            hot.insert(format!("doc:{d}"));
        }
        if !f.host.is_empty() && f.host != "-" {
            hot.insert(format!("host:{}", f.host.to_lowercase()));
        }
    }
    // Graph.
    let mut graph = Graph::default();
    for n in &ins.graph.nodes {
        let kind = match n.kind.as_str() {
            "person" => NodeKind::Person,
            "doc" => NodeKind::Document,
            "pc" => NodeKind::Workstation,
            "printer" => NodeKind::Printer,
            "share" => NodeKind::Share,
            "host" => NodeKind::Server,
            "domain" | "forest" => NodeKind::Domain,
            "pki" | "ca" => NodeKind::Pki,
            _ => continue,
        };
        graph.nodes.push(GraphNode {
            id: n.id.clone(),
            kind,
            label: n.label.clone(),
            critical: hot.contains(&n.id) || hot.contains(&n.id.to_lowercase()),
        });
    }
    let ids: BTreeSet<&str> = graph.nodes.iter().map(|n| n.id.as_str()).collect();
    for e in &ins.graph.edges {
        if ids.contains(e.from.as_str()) && ids.contains(e.to.as_str()) {
            graph.edges.push(GraphEdge {
                from: e.from.clone(),
                to: e.to.clone(),
            });
        }
    }
    // Network map.
    let mut netmap = NetMap::default();
    for n in &ins.netmap.nodes {
        let kind = match n.kind {
            NetKind::Forest | NetKind::Domain => RK::Domain,
            NetKind::Server => RK::Server,
            NetKind::Workstation => RK::Workstation,
            NetKind::User => RK::User,
        };
        let role = (kind == RK::Server).then(|| {
            n.roles
                .iter()
                .find_map(|r| match r.as_str() {
                    "dc" => Some(ServerRole::Dc),
                    "pki" => Some(ServerRole::Pki),
                    "file" => Some(ServerRole::File),
                    "mail" => Some(ServerRole::Mail),
                    "print" => Some(ServerRole::Print),
                    "web" => Some(ServerRole::Web),
                    "db" => Some(ServerRole::Db),
                    _ => None,
                })
                .unwrap_or(ServerRole::Other)
        });
        netmap.nodes.push(NetNode {
            id: n.id.clone(),
            parent: n.parent.clone(),
            kind,
            label: n.label.clone(),
            role,
            critical: hot.contains(&n.id.to_lowercase()),
        });
        for s in &n.shares {
            netmap.nodes.push(NetNode {
                id: format!("{}/share:{s}", n.id),
                parent: Some(n.id.clone()),
                kind: RK::Share,
                label: s.clone(),
                role: None,
                critical: false,
            });
        }
        for p in &n.printers {
            netmap.nodes.push(NetNode {
                id: format!("{}/printer:{p}", n.id),
                parent: Some(n.id.clone()),
                kind: RK::Printer,
                label: p.clone(),
                role: None,
                critical: false,
            });
        }
    }
    let timeline = Timeline {
        events: timeline_events(c)
            .into_iter()
            .map(|(lane, year, label)| TimelineEvent {
                lane: match lane {
                    "software" => Lane::Software,
                    "certificates" => Lane::Certificates,
                    "wayback" => Lane::Wayback,
                    _ => Lane::Documents,
                },
                year,
                label,
            })
            .collect(),
    };
    // Activity heat map (true 7×24 grid).
    let act = &a.activity;
    let activity = if act.total == 0 {
        Heatmap::default()
    } else {
        Heatmap {
            matrix: act.matrix.clone(),
            hours: act.hours.clone(),
            weekdays: act.weekdays.clone(),
            out_of_hours: Some(act.out_of_hours),
            tz: act.tz.clone(),
            ..Default::default()
        }
    };
    foca_report::Visuals {
        graph,
        netmap,
        timeline,
        activity,
    }
}

#[cfg(test)]
mod kev_group_tests {
    use super::*;
    use foca_analysis::kev::{KevEntry, KevSubject, SubjectKind};

    #[test]
    fn multiple_techs_on_one_host_do_not_collide_and_same_tech_across_hosts_dedupes() {
        let a = Analysis::default();
        let ins = Insights {
            kev: vec![
                foca_analysis::kev::KevMatch {
                    product_key: "apache_httpd".into(),
                    product_label: "Apache HTTP Server".into(),
                    subject: KevSubject {
                        kind: SubjectKind::Tech,
                        id: "erphealth.example.test".into(),
                        name: "Apache HTTP Server 2.4.58".into(),
                        ver: String::new(),
                        eol: false,
                        eol_date: None,
                        docs: 0,
                        context: String::new(),
                    },
                    total: 1,
                    ransomware: 0,
                    after_eol: 0,
                    cves: vec![],
                    confidence: "likely".into(),
                    score: 85,
                    sev: Severity::High,
                    title: String::new(),
                    reason: String::new(),
                },
                foca_analysis::kev::KevMatch {
                    product_key: "php".into(),
                    product_label: "PHP".into(),
                    subject: KevSubject {
                        kind: SubjectKind::Tech,
                        id: "erphealth.example.test".into(),
                        name: "PHP 7.2.0".into(),
                        ver: String::new(),
                        eol: false,
                        eol_date: None,
                        docs: 0,
                        context: String::new(),
                    },
                    total: 1,
                    ransomware: 0,
                    after_eol: 0,
                    cves: vec![],
                    confidence: "likely".into(),
                    score: 85,
                    sev: Severity::High,
                    title: String::new(),
                    reason: String::new(),
                },
                foca_analysis::kev::KevMatch {
                    product_key: "apache_httpd".into(),
                    product_label: "Apache HTTP Server".into(),
                    subject: KevSubject {
                        kind: SubjectKind::Tech,
                        id: "portal.example.test".into(),
                        name: "Apache HTTP Server 2.4.58".into(),
                        ver: String::new(),
                        eol: false,
                        eol_date: None,
                        docs: 0,
                        context: String::new(),
                    },
                    total: 30,
                    ransomware: 0,
                    after_eol: 0,
                    cves: vec![],
                    confidence: "likely".into(),
                    score: 85,
                    sev: Severity::High,
                    title: String::new(),
                    reason: String::new(),
                },
            ],
            ..Default::default()
        };
        let _ = std::any::type_name::<KevEntry>();
        let fs = findings(&a, &ins, "2026-11-25T00:00:00", None);
        assert_eq!(
            fs.len(),
            2,
            "expected 2 grouped KEV findings (apache + php)"
        );
        let ap = fs
            .iter()
            .find(|f| f.title.contains("Apache HTTP Server"))
            .unwrap();
        assert_eq!(ap.host, "erphealth.example.test (+1)");
        assert!(ap.description.contains("portal.example.test"));
        assert!(ap.evidence.contains("… и ещё 30"));
        let php = fs.iter().find(|f| f.title.contains("PHP")).unwrap();
        assert_eq!(php.host, "erphealth.example.test");
    }
}
