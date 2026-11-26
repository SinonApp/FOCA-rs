//! Automatic org chart: departments, organizations and the roles of people,
//! assembled from what the documents leak.
//!
//! Department evidence, each with a weight (0-100):
//! * folders of local profile paths (`C:\Users\i.petrenko\Documents\HR\…`): 60 for the path user;
//! * UNC shares and their first folders (`\\SRV\Buh\Zvit\…`): 55 for the path user, 45 for the
//!   document author and last editor;
//! * printer names (`\\PRN01\HP-Buh-2F`): 40 for the people of the printed document;
//! * the `OU` (85) and job title `T` (80) of qualified signature certificates (КЕП);
//! * custom document properties named like *Department* / *Відділ* / *Отдел*: 70 for the author.
//!
//! Names are matched against a small Ukrainian/Russian/English/transliterated dictionary of
//! department words; an unknown share name becomes a candidate department only when two or more
//! people are tied to it. A person's confidence for a department combines the independent
//! weights as `1 − Π(1 − w)`, capped at 95; the person is assigned when it reaches 40.
//!
//! Roles per person: `author`, `editor` (last saved by, tracked changes), `reviewer` (comments),
//! `signer`, `approver` (signer whose certificate title is a head/director position),
//! `printed_by`.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::{DocStatus, Metadata, PathKind, PersonRole};
use serde::Serialize;

use crate::people::Logins;
use crate::util::unc_parts;
use crate::{Analysis, DocFacts, DocInput};

/// A piece of evidence for an org chart statement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Evidence {
    /// `local_path` | `unc_path` | `printer` | `cert_ou` | `cert_title` | `custom_field`.
    pub source: String,
    /// The observed value (path, printer, OU…).
    pub value: String,
    pub doc: Option<u64>,
    pub weight: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Member {
    pub login: String,
    /// 0-95.
    pub confidence: u8,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Department {
    /// `dept:finance` for dictionary departments, `dept:share:<name>` for unknown shares.
    pub id: String,
    /// Dictionary key (`finance`, `hr`, …; the UI localizes `org.dept.<key>`) or `share`.
    pub key: String,
    /// Spellings seen in the documents (`Buh`, `Бухгалтерія`).
    pub labels: Vec<String>,
    /// From the dictionary (`true`) or an unknown share name.
    pub known: bool,
    /// Assigned members (confidence ≥ 40), strongest first.
    pub members: Vec<Member>,
    /// Weaker ties (confidence < 40).
    pub candidates: Vec<Member>,
    /// Documents that mention the department.
    pub docs: Vec<u64>,
    /// Confidence that the department exists: the best single evidence weight.
    pub confidence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Organization {
    pub name: String,
    pub edrpou: Option<String>,
    /// `company` (document property) | `cert` (signature certificate).
    pub sources: Vec<String>,
    pub docs: Vec<u64>,
    pub people: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrgPerson {
    pub login: String,
    pub name: String,
    /// Role → number of documents.
    pub roles: BTreeMap<String, u32>,
    pub primary_role: String,
    /// Job title from a certificate.
    pub title: Option<String>,
    /// Assigned department id.
    pub department: Option<String>,
    pub dept_confidence: u8,
    /// Organization names the person signed or authored for.
    pub organizations: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OrgChart {
    pub organizations: Vec<Organization>,
    pub departments: Vec<Department>,
    pub people: Vec<OrgPerson>,
}

/// Minimum person-department confidence to assign a member.
pub const ASSIGN_MIN: u8 = 40;

/// Department dictionary: key, exact tokens, token prefixes.
#[rustfmt::skip]
const DEPTS: &[(&str, &[&str], &[&str])] = &[
    ("finance", &["buh", "bukh", "buch", "fin", "finance", "accounting", "бух", "бухгалтерия", "бухгалтерія", "финансы", "фінанси", "treasury", "payroll", "zarplata", "зарплата", "kassa", "каса", "касса"],
        &["бухгалт", "buhgalt", "bukhgalt", "финанс", "фінанс", "account"]),
    ("hr", &["hr", "hrd", "kadry", "kadri", "кадры", "кадри", "personnel", "staff", "персонал"],
        &["кадр", "kadr", "recruit", "human"]),
    ("legal", &["legal", "law", "yur", "jur", "юр", "юристы", "юристи", "pravo"],
        &["юрид", "yurid", "jurid", "юрист", "yurist", "lawyer"]),
    ("it", &["it", "ит", "іт", "asu", "асу", "helpdesk", "sysadmin", "admins", "oit", "ikt", "ict"],
        &["informat", "информац", "інформац", "helpdesk", "servicedesk"]),
    ("sales", &["sales", "sale", "продажи", "продажі", "sbyt", "сбыт", "збут", "commercial"],
        &["продаж", "prodazh", "коммерч", "комерц"]),
    ("marketing", &["marketing", "mkt", "маркетинг", "pr", "smm", "reklama", "реклама"],
        &["маркет", "market"]),
    ("management", &["director", "directorate", "management", "mgmt", "дирекция", "дирекція", "керівництво", "руководство", "board", "ceo", "priemnaya", "приемная", "приймальня", "secretariat", "секретариат", "секретаріат", "канцелярия", "канцелярія", "kancelyariya", "kantselyariya"],
        &["директор", "direkt", "керівн", "руковод"]),
    ("procurement", &["procurement", "purchasing", "zakupki", "закупки", "закупівлі", "snab", "снабжение", "постачання", "tender", "тендер", "tenders"],
        &["закуп", "zakup", "снабж", "постач", "tender"]),
    ("logistics", &["logistics", "sklad", "склад", "warehouse", "logistika", "логистика", "логістика", "transport", "транспорт"],
        &["логист", "логіст", "logist"]),
    ("security", &["security", "sb", "сб", "безопасность", "безпека", "infosec", "ib", "иб", "кзи", "кзі", "tzi", "тзі"],
        &["безопасн", "безпек", "secur"]),
    ("production", &["production", "proizvodstvo", "производство", "виробництво", "ceh", "цех", "workshop"],
        &["производ", "виробн", "proizvod"]),
    ("engineering", &["engineering", "eng", "pto", "пто", "kb", "кб", "cad"],
        &["инженер", "інженер", "engineer", "конструк", "konstrukt"]),
    ("planning", &["planning", "пэо", "пео", "peo", "economics", "ekonom"],
        &["эконом", "економ", "ekonom", "планов", "planov"]),
    ("quality", &["qa", "qc", "quality", "якість", "качество", "otk", "отк"],
        &["quality"]),
];

/// Share and folder names that say nothing about a department.
#[rustfmt::skip]
const GENERIC: &[&str] = &[
    "users", "user", "home", "homes", "public", "share", "shares", "shared", "common", "общие",
    "общая", "загальні", "загальна", "temp", "tmp", "scan", "scans", "docs", "doc", "documents",
    "data", "files", "file", "archive", "archiv", "backup", "backups", "profiles", "profile",
    "desktop", "downloads", "мои документы", "мої документи", "c$", "d$", "e$", "admin$", "ipc$",
    "netlogon", "sysvol", "print$", "projects", "project", "distrib", "soft", "software", "install",
    "dfs", "root", "work", "обмен", "обмін", "exchange", "obmen", "out", "in", "new", "old",
];

/// Folders of a local profile path that are not department hints.
const PROFILE: &[&str] = &[
    "users",
    "documents and settings",
    "home",
    "documents",
    "my documents",
    "desktop",
    "downloads",
    "мои документы",
    "мої документи",
    "рабочий стол",
    "робочий стіл",
    "appdata",
    "local",
    "roaming",
    "temp",
    "onedrive",
];

/// Job title words of a head/director (makes a signer an approver).
const HEAD_WORDS: &[&str] = &[
    "директор",
    "director",
    "керівник",
    "руководител",
    "начальник",
    "голова",
    "head",
    "chief",
    "заступник",
    "заместител",
    "deputy",
    "ceo",
    "cfo",
    "cto",
    "головний",
    "главный",
];

fn tokens(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.trim_end_matches(|c: char| c.is_ascii_digit()).to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Dictionary department of a name (folder, share, printer, OU, title), if any.
pub fn dept_of(name: &str) -> Option<&'static str> {
    let toks = tokens(name);
    for (key, exact, prefixes) in DEPTS {
        if toks
            .iter()
            .any(|t| exact.contains(&t.as_str()) || prefixes.iter().any(|p| t.starts_with(p)))
        {
            return Some(key);
        }
    }
    None
}

fn is_generic(name: &str) -> bool {
    let l = name.trim().to_lowercase();
    l.len() < 2 || GENERIC.contains(&l.as_str()) || l.ends_with('$')
}

/// Folders of a local path after the profile part: `C:\Users\u\Documents\HR\x.docx` → `[HR]`.
fn local_folders(path: &str, user: Option<&str>) -> Vec<String> {
    let p = path.strip_prefix("file:///").unwrap_or(path);
    let mut parts: Vec<&str> = p.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    if parts.last().is_some_and(|l| l.contains('.')) {
        parts.pop();
    }
    parts
        .into_iter()
        .filter(|s| !(s.len() == 2 && s.ends_with(':')))
        .filter(|s| !PROFILE.contains(&s.to_lowercase().as_str()))
        .filter(|s| user.is_none_or(|u| !s.eq_ignore_ascii_case(u)))
        .map(str::to_string)
        .collect()
}

/// Spellings with weights, ЄДРПОУ, sources, documents, people.
type OrgAcc = (
    BTreeMap<String, u32>,
    Option<String>,
    BTreeSet<String>,
    BTreeSet<u64>,
    BTreeSet<String>,
);

#[derive(Default)]
struct DeptAcc {
    labels: BTreeSet<String>,
    docs: BTreeSet<u64>,
    best: u8,
    people: BTreeMap<String, BTreeSet<Evidence>>,
}

fn combine(ws: impl Iterator<Item = u8>) -> u8 {
    let miss: f64 = ws.map(|w| 1.0 - f64::from(w.min(99)) / 100.0).product();
    (((1.0 - miss) * 100.0).round() as u8).min(95)
}

fn org_key(name: &str) -> String {
    #[rustfmt::skip]
    const FORMS: &[&str] = &[
        "тов", "ооо", "llc", "ltd", "inc", "пат", "прат", "ат", "ао", "пао", "оао", "зао", "дп",
        "кп", "фоп", "gmbh", "jsc", "plc", "corp", "corporation", "company",
    ];
    tokens(name)
        .into_iter()
        .filter(|t| !FORMS.contains(&t.as_str()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Builds the org chart.
pub fn build(inputs: &[DocInput], a: &Analysis) -> OrgChart {
    let logins = Logins::new(&a.people);
    let facts: BTreeMap<u64, &DocFacts> = a.facts.iter().map(|f| (f.id, f)).collect();
    let mut depts: BTreeMap<String, DeptAcc> = BTreeMap::new();
    let mut orgs: BTreeMap<String, OrgAcc> = BTreeMap::new();
    let mut roles: BTreeMap<String, BTreeMap<&'static str, BTreeSet<u64>>> = BTreeMap::new();
    let mut titles: BTreeMap<String, String> = BTreeMap::new();
    let mut add_role = |login: &str, role: &'static str, doc: u64| {
        roles
            .entry(login.to_string())
            .or_default()
            .entry(role)
            .or_default()
            .insert(doc);
    };

    let mut tie = |dept_id: String, label: &str, who: &[String], ev: Evidence| {
        let d = depts.entry(dept_id).or_default();
        d.labels.insert(label.to_string());
        if let Some(doc) = ev.doc {
            d.docs.insert(doc);
        }
        d.best = d.best.max(ev.weight);
        for w in who {
            d.people.entry(w.clone()).or_default().insert(ev.clone());
        }
    };
    let id_for = |name: &str| -> Option<String> {
        dept_of(name)
            .map(|k| format!("dept:{k}"))
            .or_else(|| (!is_generic(name)).then(|| format!("dept:share:{}", name.to_lowercase())))
    };

    let mut docs: Vec<(&DocInput, &Metadata)> = inputs
        .iter()
        .filter(|i| !i.deleted && i.doc.status == DocStatus::Analyzed)
        .filter_map(|i| i.doc.metadata.as_ref().map(|m| (i, m)))
        .collect();
    docs.sort_by_key(|(i, _)| i.doc.id);
    for (inp, m) in docs {
        let id = inp.doc.id;
        let f = facts.get(&id).copied();
        let mut owners: Vec<String> = Vec::new();
        if let Some(f) = f {
            owners.extend(f.author.iter().cloned());
            owners.extend(f.last_modified_by.iter().cloned());
            if let Some(au) = &f.author {
                add_role(au, "author", id);
            }
            if let Some(lm) = f
                .last_modified_by
                .as_ref()
                .filter(|l| f.author.as_ref() != Some(l))
            {
                add_role(lm, "editor", id);
            }
            for r in &f.revisions {
                if let Some(w) = &r.who {
                    let w = logins.get(w).unwrap_or_else(|| w.clone());
                    let role = if r.kind == "com" {
                        "reviewer"
                    } else {
                        "editor"
                    };
                    if f.author.as_ref() != Some(&w) || role == "editor" {
                        add_role(&w, role, id);
                    }
                }
            }
        }
        owners.sort();
        owners.dedup();
        let mut printed_by: Vec<String> = Vec::new();
        for p in &m.people {
            if p.role == PersonRole::PrintedBy {
                if let Some(l) = logins.get(&p.name) {
                    add_role(&l, "printed_by", id);
                    printed_by.push(l);
                }
            }
        }

        // Paths.
        for p in &m.paths {
            let user = p.user.as_deref().and_then(|u| logins.get(u));
            match p.kind {
                PathKind::Unc | PathKind::FileUrl if unc_parts(&p.path).is_some() => {
                    let Some((_, Some(share), rest)) = unc_parts(&p.path) else {
                        continue;
                    };
                    let (who, w): (Vec<String>, u8) = match &user {
                        Some(u) => (vec![u.clone()], 55),
                        None => (owners.clone(), 45),
                    };
                    let mut names = vec![share.clone()];
                    names.extend(rest.first().cloned());
                    let mut done = false;
                    for n in names {
                        if done {
                            break;
                        }
                        if let Some(dept) = id_for(&n) {
                            done = !dept.starts_with("dept:share:");
                            if dept.starts_with("dept:share:") && n != share {
                                continue;
                            }
                            tie(
                                dept,
                                &n,
                                &who,
                                Evidence {
                                    source: "unc_path".into(),
                                    value: p.path.clone(),
                                    doc: Some(id),
                                    weight: if done { w } else { w.min(35) },
                                },
                            );
                        }
                    }
                }
                _ => {
                    let raw_user = p.user.as_deref();
                    for folder in local_folders(&p.path, raw_user) {
                        if let Some(k) = dept_of(&folder) {
                            let who = user
                                .clone()
                                .map(|u| vec![u])
                                .unwrap_or_else(|| owners.clone());
                            tie(
                                format!("dept:{k}"),
                                &folder,
                                &who,
                                Evidence {
                                    source: "local_path".into(),
                                    value: p.path.clone(),
                                    doc: Some(id),
                                    weight: if user.is_some() { 60 } else { 45 },
                                },
                            );
                            break;
                        }
                    }
                }
            }
        }
        // Printers.
        for pr in &m.printers {
            let name = pr.rsplit(['\\', '/']).next().unwrap_or(pr);
            if let Some(k) = dept_of(name) {
                let mut who = owners.clone();
                who.extend(printed_by.iter().cloned());
                who.sort();
                who.dedup();
                tie(
                    format!("dept:{k}"),
                    name,
                    &who,
                    Evidence {
                        source: "printer".into(),
                        value: pr.clone(),
                        doc: Some(id),
                        weight: 40,
                    },
                );
            }
        }
        // Custom properties.
        for (k, v) in &m.custom {
            let kl = k.to_lowercase();
            if [
                "department",
                "dept",
                "division",
                "отдел",
                "відділ",
                "подраздел",
                "підрозділ",
                "управлін",
                "управлен",
            ]
            .iter()
            .any(|w| kl.contains(w))
                && !is_generic(v)
                && !v.trim().eq_ignore_ascii_case(k.trim())
                && !["department", "division", "відділ", "отдел"]
                    .contains(&v.trim().to_lowercase().as_str())
            {
                let dept = dept_of(v)
                    .map(|k| format!("dept:{k}"))
                    .unwrap_or_else(|| format!("dept:share:{}", v.trim().to_lowercase()));
                tie(
                    dept,
                    v.trim(),
                    &f.and_then(|f| f.author.clone())
                        .into_iter()
                        .collect::<Vec<_>>(),
                    Evidence {
                        source: "custom_field".into(),
                        value: format!("{k}: {v}"),
                        doc: Some(id),
                        weight: 70,
                    },
                );
            }
        }
        // Company.
        if let Some(c) = m.company.as_deref().map(str::trim).filter(|c| c.len() > 1) {
            let key = org_key(c);
            if !key.is_empty() {
                let e = orgs.entry(key).or_default();
                *e.0.entry(c.to_string()).or_default() += 1;
                e.2.insert("company".into());
                e.3.insert(id);
                e.4.extend(f.and_then(|f| f.author.clone()));
            }
        }
        // Signatures.
        for s in &m.signatures {
            let Some(c) = &s.signer else { continue };
            let name = c
                .common_name
                .clone()
                .or_else(|| match (&c.given_name, &c.surname) {
                    (Some(g), Some(s)) => Some(format!("{g} {s}")),
                    _ => None,
                });
            let login = name.as_deref().and_then(|n| logins.get(n));
            if let Some(l) = &login {
                add_role(l, "signer", id);
                if let Some(t) = &c.title {
                    titles.entry(l.clone()).or_insert_with(|| t.clone());
                    let tl = t.to_lowercase();
                    if HEAD_WORDS.iter().any(|w| tl.contains(w)) {
                        add_role(l, "approver", id);
                    }
                }
            }
            let who: Vec<String> = login.iter().cloned().collect();
            if let Some(ou) = c.org_unit.as_deref().filter(|o| !o.trim().is_empty()) {
                let dept = dept_of(ou)
                    .map(|k| format!("dept:{k}"))
                    .unwrap_or_else(|| format!("dept:share:{}", ou.trim().to_lowercase()));
                tie(
                    dept,
                    ou.trim(),
                    &who,
                    Evidence {
                        source: "cert_ou".into(),
                        value: ou.to_string(),
                        doc: Some(id),
                        weight: 85,
                    },
                );
            }
            if let Some(t) = &c.title {
                if let Some(k) = dept_of(t) {
                    tie(
                        format!("dept:{k}"),
                        t,
                        &who,
                        Evidence {
                            source: "cert_title".into(),
                            value: t.clone(),
                            doc: Some(id),
                            weight: 80,
                        },
                    );
                }
            }
            if let Some(o) = c
                .organization
                .as_deref()
                .map(str::trim)
                .filter(|o| o.len() > 1)
            {
                let key = org_key(o);
                if !key.is_empty() {
                    let e = orgs.entry(key).or_default();
                    *e.0.entry(o.to_string()).or_default() += 2;
                    if e.1.is_none() {
                        e.1 = c.edrpou.clone();
                    }
                    e.2.insert("cert".into());
                    e.3.insert(id);
                    e.4.extend(login.clone());
                }
            }
        }
    }

    // Departments.
    let mut person_best: BTreeMap<String, (u8, String)> = BTreeMap::new();
    let mut departments: Vec<Department> = Vec::new();
    for (id, acc) in depts {
        let known = !id.starts_with("dept:share:");
        // Unknown names need two people (or a certificate/custom field) to count.
        let strong_source = acc
            .people
            .values()
            .flatten()
            .any(|e| matches!(e.source.as_str(), "cert_ou" | "custom_field"));
        if !known && acc.people.len() < 2 && !strong_source {
            continue;
        }
        let mut members: Vec<Member> = Vec::new();
        let mut candidates: Vec<Member> = Vec::new();
        for (login, evs) in acc.people {
            let conf = combine(evs.iter().map(|e| e.weight));
            let mut ev: Vec<Evidence> = evs.into_iter().collect();
            ev.sort_by(|a, b| b.weight.cmp(&a.weight).then(a.cmp(b)));
            ev.truncate(6);
            let m = Member {
                login: login.clone(),
                confidence: conf,
                evidence: ev,
            };
            if conf >= ASSIGN_MIN {
                let e = person_best.entry(login).or_insert((0, String::new()));
                if conf > e.0 || (conf == e.0 && known && e.1.starts_with("dept:share:")) {
                    *e = (conf, id.clone());
                }
                members.push(m);
            } else {
                candidates.push(m);
            }
        }
        members.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.login.cmp(&b.login)));
        candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.login.cmp(&b.login)));
        let key = if known {
            id.trim_start_matches("dept:").to_string()
        } else {
            "share".to_string()
        };
        departments.push(Department {
            id,
            key,
            labels: acc.labels.into_iter().collect(),
            known,
            members,
            candidates,
            docs: acc.docs.into_iter().collect(),
            confidence: acc.best,
        });
    }
    departments.sort_by(|a, b| {
        b.members
            .len()
            .cmp(&a.members.len())
            .then(b.confidence.cmp(&a.confidence))
            .then(a.id.cmp(&b.id))
    });

    // Organizations.
    let mut organizations: Vec<Organization> = orgs
        .into_values()
        .map(|(names, edrpou, src, docs, people)| {
            let name = names
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
                .map(|(n, _)| n.clone())
                .unwrap_or_default();
            Organization {
                name,
                edrpou,
                sources: src.into_iter().collect(),
                docs: docs.into_iter().collect(),
                people: people.into_iter().collect(),
            }
        })
        .collect();
    organizations.sort_by(|a, b| b.docs.len().cmp(&a.docs.len()).then(a.name.cmp(&b.name)));

    // People.
    const WEIGHT: &[(&str, u32)] = &[
        ("approver", 5),
        ("signer", 4),
        ("reviewer", 3),
        ("author", 2),
        ("editor", 1),
        ("printed_by", 1),
    ];
    let people: Vec<OrgPerson> = a
        .people
        .iter()
        .filter(|p| !p.service)
        .map(|p| {
            let r: BTreeMap<String, u32> = roles
                .get(&p.login)
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.to_string(), v.len() as u32))
                        .collect()
                })
                .unwrap_or_default();
            let primary = WEIGHT
                .iter()
                .filter_map(|(k, w)| r.get(*k).map(|c| (c * w, *k)))
                .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(a.1)))
                .map(|x| x.1.to_string())
                .unwrap_or_else(|| "mentioned".into());
            let (conf, dept) = person_best
                .get(&p.login)
                .cloned()
                .map(|(c, d)| (c, Some(d)))
                .unwrap_or((0, None));
            OrgPerson {
                login: p.login.clone(),
                name: p.name.clone(),
                roles: r,
                primary_role: primary,
                title: titles.get(&p.login).cloned(),
                department: dept,
                dept_confidence: conf,
                organizations: organizations
                    .iter()
                    .filter(|o| o.people.contains(&p.login))
                    .map(|o| o.name.clone())
                    .collect(),
            }
        })
        .collect();

    OrgChart {
        organizations,
        departments,
        people,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary() {
        assert_eq!(dept_of("Buh"), Some("finance"));
        assert_eq!(dept_of("Бухгалтерія"), Some("finance"));
        assert_eq!(dept_of("HP-Buh-2F"), Some("finance"));
        assert_eq!(dept_of("Відділ кадрів"), Some("hr"));
        assert_eq!(dept_of("HR2"), Some("hr"));
        assert_eq!(dept_of("Головний бухгалтер"), Some("finance"));
        assert_eq!(dept_of("Юридичний департамент"), Some("legal"));
        assert_eq!(dept_of("Projects"), None);
        assert!(is_generic("Public") && is_generic("C$") && !is_generic("Proekty"));
        assert_eq!(
            local_folders(
                r"C:\Users\i.petrenko\Documents\HR\2024\x.docx",
                Some("i.petrenko")
            ),
            vec!["HR", "2024"]
        );
        assert_eq!(combine([60, 45].into_iter()), 78);
        assert_eq!(combine([99, 99, 99].into_iter()), 95);
    }
}
