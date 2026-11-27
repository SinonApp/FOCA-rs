//! Findings: generation rules with severity, MITRE mapping and provenance; stable ids
//! (hash of rule and object) so triage survives a rescan; project risk.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::{Finding, FindingProvenance, FindingRel, Pattern, Person, Secret, Software};
use foca_core::{FindingStatus, Severity};
use serde::{Deserialize, Serialize};

use crate::assess::draft::Draft;
use crate::{DocFacts, OsInfo, PrevState};

/// A secret together with the context used as evidence.
#[derive(Debug, Clone)]
pub struct SecretRec {
    pub secret: Secret,
    pub title: String,
    pub context: String,
}

/// Software data older than this many years is considered historic and its EOL severity is
/// lowered.
pub const HISTORIC_YEARS: i32 = 3;

fn year_of(s: &str) -> Option<i32> {
    s.get(..4)
        .and_then(|y| y.parse().ok())
        .filter(|y| *y > 1980)
}

/// For documents served from a web archive (Wayback, arquivo.pt, archive.today), returns the
/// capture year if it is known.
fn archive_capture(url: &str) -> Option<Option<i32>> {
    let u = url.to_ascii_lowercase();
    for m in ["web.archive.org/web/", "arquivo.pt/wayback/", "/wayback/"] {
        if let Some(i) = u.find(m) {
            return Some(year_of(&u[i + m.len()..]));
        }
    }
    if u.contains("archive.today/") || u.contains("archive.ph/") || u.contains("archive.is/") {
        return Some(None);
    }
    None
}

/// If every document of a finding is historic (from a web archive or older than
/// [`HISTORIC_YEARS`]), returns the year of the most recent data: the document date, otherwise
/// the archive capture year.
fn historic_year(docs: &[&DocFacts], now: &str) -> Option<i32> {
    let now_y = year_of(now)?;
    let mut newest: Option<i32> = None;
    for d in docs {
        let y = d
            .modified
            .as_deref()
            .and_then(year_of)
            .max(d.created.as_deref().and_then(year_of));
        let arch = d.url.as_deref().and_then(archive_capture);
        let old = y.is_some_and(|y| y <= now_y - HISTORIC_YEARS);
        if arch.is_none() && !old {
            return None;
        }
        let yy = y.or(arch.flatten());
        newest = match (newest, yy) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }
    newest.or(Some(now_y))
}

fn sev_down(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        _ => Severity::Info,
    }
}

/// Lowers the severity of findings based on historic data by one level and notes it in the
/// evidence.
fn mark_historic(f: &mut Draft, docs: &[&DocFacts], now: &str) {
    if let Some(y) = historic_year(docs, now) {
        f.sev = sev_down(f.sev);
        f.evidence.push_str(&format!(
            "\nИсторические данные ({y}): документы из веб-архива или старше {HISTORIC_YEARS} лет, важность понижена"
        ));
    }
}

/// Input for the finding rules.
pub struct Ctx<'a> {
    pub docs: &'a [DocFacts],
    pub people: &'a [Person],
    pub software: &'a [Software],
    pub os: &'a [OsInfo],
    pub secrets: &'a [SecretRec],
    pub patterns: &'a [Pattern],
    pub now: &'a str,
    pub prev: &'a PrevState,
}

/// Formats a count with the matching Russian plural form: `one` for 1, 21, 31, …, `few` for
/// 2-4, 22-24, …, `many` otherwise (including 11-14).
pub fn ru_n(n: usize, one: &str, few: &str, many: &str) -> String {
    let w = match (n % 10, n % 100) {
        (_, 11..=14) => many,
        (1, _) => one,
        (2..=4, _) => few,
        _ => many,
    };
    format!("{n} {w}")
}

/// Returns `true` when Russian uses the singular form for `n` (1, 21, 31, … but not 11).
pub fn ru_one(n: usize) -> bool {
    n % 10 == 1 && n % 100 != 11
}

/// Builds a software label without repeating the version: `Acrobat Distiller 5.0.5` +
/// `5.0.5` → `Acrobat Distiller 5.0.5`; `Microsoft Word 2010` + `14` →
/// `Microsoft Word 2010 (14)`.
pub fn sw_label(name: &str, ver: &str) -> String {
    if ver.is_empty() || name.contains(ver) {
        name.to_string()
    } else {
        format!("{name} ({ver})")
    }
}

/// Returns a stable finding id derived from the rule and the object (document key,
/// software id, …).
pub fn finding_id(rule: &str, key: &str) -> u64 {
    crate::util::stable_id(&["finding", rule, key])
}

fn secret_rule(rule: &str) -> &'static str {
    match rule {
        "rdp_password_51" => "rdp-password",
        "ica_clearpassword" => "ica-password",
        _ => "secret",
    }
}

/// Returns the id of the finding produced by a secret (`doc_key` is the document key).
pub fn secret_finding_id(s: &Secret, doc_key: &str) -> u64 {
    if s.kind == "host" {
        finding_id("internal-addresses", doc_key)
    } else {
        finding_id(
            secret_rule(&s.rule),
            &format!("{doc_key}|{}|{}", s.rule, s.value.expose()),
        )
    }
}

fn uniq<T: Ord + Clone>(v: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for x in v {
        if seen.insert(x.clone()) {
            out.push(x);
        }
    }
    out
}

fn top_people(docs: &[&DocFacts], n: usize) -> Vec<String> {
    let mut c: BTreeMap<&str, usize> = BTreeMap::new();
    for d in docs {
        for p in &d.people {
            *c.entry(p.as_str()).or_default() += 1;
        }
    }
    let mut v: Vec<(&str, usize)> = c.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.into_iter().take(n).map(|(s, _)| s.to_string()).collect()
}

const SENSITIVE_SHEETS: &[&str] = &[
    "парол",
    "password",
    "зарплат",
    "salary",
    "secret",
    "секрет",
    "логін",
    "логин",
    "login",
    "доступ",
    "access",
    "кадр",
    "персонал",
    "hr",
];

/// Builds the findings.
pub fn build(ctx: &Ctx) -> Vec<Finding> {
    let an: Vec<&DocFacts> = ctx.docs.iter().filter(|d| d.analyzed).collect();
    let by_id: BTreeMap<u64, &DocFacts> = an.iter().map(|d| (d.id, *d)).collect();
    let mut drafts: Vec<Draft> = Vec::new();

    // Secrets.
    let mut host_secrets: BTreeMap<u64, Vec<&SecretRec>> = BTreeMap::new();
    for s in ctx.secrets {
        let Some(d) = by_id.get(&s.secret.doc) else {
            continue;
        };
        if s.secret.kind == "host" {
            host_secrets.entry(d.id).or_default().push(s);
            continue;
        }
        let (rule, title, sev, rec): (&'static str, String, Severity, &'static str) =
            match s.secret.rule.as_str() {
                "rdp_password_51" => (
                    "rdp-password",
                    format!("RDP-файл с сохранённым паролем ({})", d.name),
                    Severity::High,
                    "Удалить файл с сайта; сменить пароль учётной записи из файла; запретить сохранение паролей в RDP-клиенте групповой политикой.",
                ),
                "ica_clearpassword" => (
                    "ica-password",
                    format!("ICA-файл с паролем в открытом виде ({})", d.name),
                    Severity::Critical,
                    "Немедленно сменить пароль, удалить файл с сайта, запретить ClearPassword в конфигурации Citrix StoreFront.",
                ),
                _ => (
                    "secret",
                    s.title.clone(),
                    s.secret.sev,
                    "Немедленно сменить (отозвать) секрет, удалить документ с сайта и из кэшей поисковиков, проверить журналы использования.",
                ),
            };
        let mut f = Draft::new(
            rule,
            format!("{}|{}|{}", d.key, s.secret.rule, s.secret.value.expose()),
            title,
            sev,
        );
        f.source = "Секреты в документах";
        f.module = "secrets";
        f.mitre = "T1552.001 · Unsecured Credentials: Credentials In Files";
        f.cvss = Some(super::draft::band_cvss(sev));
        f.description = format!(
            "В публично доступном документе «{}» найден секрет ({}): {}.",
            d.name, s.title, s.secret.location
        );
        f.recommendation = rec;
        f.evidence = format!("{}:\n{}", s.secret.location, s.context);
        f.docs = vec![d.id];
        f.people = d.people.clone();
        f.pcs = d.pcs.clone();
        if let Some(h) = &s.secret.host {
            if !f.pcs.contains(h) && !h.contains('.') {
                f.pcs.push(h.clone());
            }
        }
        f.fields = vec![s.secret.location.clone()];
        f.tags = vec!["secret"];
        drafts.push(f);
    }
    for (doc, list) in &host_secrets {
        let d = by_id[doc];
        let vals: Vec<String> = uniq(list.iter().map(|s| s.secret.value.expose().to_string()));
        let mut f = Draft::new(
            "internal-addresses",
            d.key.clone(),
            format!(
                "Внутренние адреса и имена хостов в документе ({})",
                vals.len()
            ),
            Severity::Low,
        );
        f.source = "Секреты в документах";
        f.module = "secrets";
        f.mitre = "T1590.005 · Gather Victim Network Information: IP Addresses";
        f.cvss = Some(3.7);
        f.description = format!(
            "Текст или поля документа «{}» раскрывают внутреннюю адресацию сети: {}.",
            d.name,
            vals.join(", ")
        );
        f.recommendation =
            "Удалять технические подробности (адреса, имена серверов) из публикуемых документов.";
        f.evidence = list
            .iter()
            .take(5)
            .map(|s| format!("{}: {}", s.secret.location, s.context))
            .collect::<Vec<_>>()
            .join("\n");
        f.docs = vec![d.id];
        f.people = d.people.clone();
        f.fields = uniq(list.iter().map(|s| s.secret.location.clone()));
        drafts.push(f);
    }

    // RDP/ICA server names.
    for d in an.iter().filter(|d| d.rdp.is_some()) {
        let r = d.rdp.clone().unwrap_or_default();
        let mut f = Draft::new(
            "remote-file",
            d.key.clone(),
            format!("Параметры удалённого доступа раскрыты в файле {}", d.name),
            Severity::Low,
        );
        f.mitre = "T1590.002 · Gather Victim Network Information: DNS";
        f.cvss = Some(3.7);
        f.description = "Опубликованный файл подключения (RDP/ICA) содержит адрес сервера, шлюз и имя пользователя по умолчанию.".into();
        f.recommendation = "Удалить файл с сайта, не публиковать служебные файлы конфигурации.";
        f.evidence = format!(
            "full address: {}\nusername: {}\ngateway: {}",
            r.full_address, r.username, r.gateway
        );
        f.docs = vec![d.id];
        f.people = d.people.clone();
        f.pcs = d.servers.clone();
        f.fields = vec![
            "full address".into(),
            "username".into(),
            "gatewayhostname".into(),
        ];
        drafts.push(f);
    }

    // Internal paths.
    let pd: Vec<&DocFacts> = an.iter().copied().filter(|d| !d.paths.is_empty()).collect();
    if !pd.is_empty() {
        let paths: Vec<String> = uniq(pd.iter().flat_map(|d| d.paths.iter().cloned()));
        let mut f = Draft::new(
            "internal-paths",
            "project",
            format!(
                "Внутренние пути и логины в метаданных {}",
                ru_n(pd.len(), "документа", "документов", "документов")
            ),
            Severity::Low,
        );
        f.mitre = "T1592 · Gather Victim Host Information";
        f.cvss = Some(3.7);
        f.description = format!(
            "Пути шаблонов, вложений и ссылок в {} раскрывают логины сотрудников и структуру файловых ресурсов.",
            ru_n(pd.len(), "документе", "документах", "документах")
        );
        f.recommendation = "Очищать метаданные перед публикацией (Инспектор документов, exiftool), внедрить проверку в процесс публикации.";
        f.evidence = paths.iter().take(6).cloned().collect::<Vec<_>>().join("\n");
        f.docs = pd.iter().map(|d| d.id).collect();
        f.people = top_people(&pd, 5);
        f.pcs = uniq(pd.iter().flat_map(|d| d.servers.iter().cloned()))
            .into_iter()
            .take(5)
            .collect();
        f.fields = vec!["paths".into()];
        drafts.push(f);
    }

    // Computer names.
    let cd: Vec<&DocFacts> = an.iter().copied().filter(|d| !d.pcs.is_empty()).collect();
    if !cd.is_empty() {
        let names: Vec<String> = uniq(cd.iter().flat_map(|d| d.pcs.iter().cloned()));
        let mut f = Draft::new(
            "internal-pcs",
            "project",
            format!(
                "Имена {} и серверов внутренней сети",
                ru_n(names.len(), "компьютера", "компьютеров", "компьютеров")
            ),
            Severity::Low,
        );
        f.mitre = "T1590 · Gather Victim Network Information";
        f.cvss = Some(3.1);
        f.description = "Метаданные документов раскрывают NetBIOS-имена рабочих станций и серверов, что помогает спланировать атаку внутри сети.".into();
        f.recommendation = "Очищать метаданные перед публикацией; не использовать в именах ПК отдел и ФИО сотрудника.";
        f.evidence = names
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        f.docs = cd.iter().map(|d| d.id).collect();
        f.pcs = names;
        f.people = top_people(&cd, 5);
        drafts.push(f);
    }

    // Outdated software.
    for s in ctx.software.iter().filter(|s| s.eol) {
        let docs: Vec<&DocFacts> = an
            .iter()
            .copied()
            .filter(|d| d.software.contains(&s.id))
            .collect();
        if docs.is_empty() {
            continue;
        }
        let since = s
            .eol_date
            .as_deref()
            .map(|d| format!(", поддержка завершена {d}"))
            .unwrap_or_else(|| ", снято с поддержки".into());
        let mut f = Draft::new(
            "eol-software",
            s.id.clone(),
            format!(
                "{} (EOL) у {}",
                s.name,
                ru_n(docs.len(), "документа", "документов", "документов")
            ),
            Severity::Medium,
        );
        f.category = "sw";
        f.source = "ПО → EOL";
        f.module = "analysis";
        f.mitre = "T1203 · Exploitation for Client Execution";
        f.description = format!(
            "{} {} в {}{}. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.",
            ru_n(docs.len(), "документ", "документа", "документов"),
            if ru_one(docs.len()) { "создан" } else { "созданы" },
            sw_label(&s.name, &s.ver),
            since
        );
        f.recommendation = "Обновить ПО до поддерживаемой версии и централизованно контролировать версии офисного ПО.";
        f.evidence = format!(
            "Сигнатура: {}\nДокументов: {}",
            sw_label(&s.name, &s.ver),
            docs.len()
        );
        f.docs = docs.iter().map(|d| d.id).collect();
        f.people = top_people(&docs, 3);
        f.tags = vec!["outdated"];
        f.fields = vec!["application".into(), "producer".into()];
        mark_historic(&mut f, &docs, ctx.now);
        drafts.push(f);
    }
    for o in ctx.os.iter().filter(|o| o.eol) {
        let docs: Vec<&DocFacts> = an
            .iter()
            .copied()
            .filter(|d| d.os.as_deref() == Some(o.id.as_str()))
            .collect();
        if docs.is_empty() {
            continue;
        }
        let mut f = Draft::new(
            "eol-os",
            o.id.clone(),
            format!(
                "Устаревшая ОС {} у {}",
                o.name,
                ru_n(docs.len(), "документа", "документов", "документов")
            ),
            Severity::Medium,
        );
        f.category = "sw";
        f.source = "ПО → EOL";
        f.module = "analysis";
        f.mitre = "T1592.002 · Gather Victim Host Information: Software";
        f.description = format!(
            "Метаданные {} указывают, что {} в {}: ОС без обновлений безопасности.",
            ru_n(docs.len(), "документа", "документов", "документов"),
            if ru_one(docs.len()) {
                "он создан"
            } else {
                "они созданы"
            },
            o.name
        );
        f.recommendation =
            "Вывести из эксплуатации или изолировать рабочие места с неподдерживаемой ОС.";
        f.evidence = format!("ОС: {}\nДокументов: {}", o.name, docs.len());
        f.docs = docs.iter().map(|d| d.id).collect();
        f.people = top_people(&docs, 3);
        f.tags = vec!["outdated"];
        f.fields = vec!["os".into()];
        mark_historic(&mut f, &docs, ctx.now);
        drafts.push(f);
    }

    // Per-document findings.
    let mut gps_docs: Vec<&DocFacts> = Vec::new();
    for d in &an {
        if !d.revisions.is_empty() {
            let dels: Vec<_> = d.revisions.iter().filter(|r| r.kind == "del").collect();
            let changes = d.revisions.iter().filter(|r| r.kind != "com").count();
            let coms = d.revisions.len() - changes;
            let (sev, title) = if changes > 0 {
                (
                    Severity::Medium,
                    format!("Исправления и удалённый текст сохранены в {}", d.name),
                )
            } else {
                (
                    Severity::Low,
                    format!("Комментарии рецензентов сохранены в {}", d.name),
                )
            };
            let mut f = Draft::new("revisions", d.key.clone(), title, sev);
            f.mitre = "T1213 · Data from Information Repositories";
            f.cvss = Some(if changes > 0 { 4.3 } else { 3.1 });
            f.description = format!(
                "В документе сохранены режим рецензирования ({}, из них {}) и {}: видны прежние формулировки и внутренняя переписка.",
                ru_n(changes, "исправление", "исправления", "исправлений"),
                ru_n(dels.len(), "удаление", "удаления", "удалений"),
                ru_n(coms, "комментарий", "комментария", "комментариев")
            );
            f.recommendation = "Принимать все исправления и удалять комментарии перед публикацией; для внешних документов использовать PDF.";
            f.evidence = d
                .revisions
                .iter()
                .take(4)
                .map(|r| {
                    format!(
                        "{} {}{}: «{}»",
                        match r.kind.as_str() {
                            "del" => "удалено",
                            "ins" => "вставлено",
                            _ => "комментарий",
                        },
                        r.who.as_deref().unwrap_or("?"),
                        r.at.as_deref()
                            .map(|a| format!(", {a}"))
                            .unwrap_or_default(),
                        r.text
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            f.docs = vec![d.id];
            f.people = d.revision_people.clone();
            f.fields = vec!["revisions".into(), "comments".into()];
            drafts.push(f);
        }
        if d.incremental > 0 || !d.old_versions.is_empty() {
            let sev = if d.old_versions.is_empty() {
                Severity::Info
            } else {
                Severity::Low
            };
            let mut f = Draft::new(
                "pdf-revisions",
                d.key.clone(),
                if d.is_pdf {
                    format!("Старые ревизии PDF сохранены в {}", d.name)
                } else {
                    format!("Предыдущие версии метаданных сохранены в {}", d.name)
                },
                sev,
            );
            f.mitre = "T1213 · Data from Information Repositories";
            f.description = if d.is_pdf {
                format!(
                    "PDF сохранён инкрементально ({} обновл.), предыдущие версии метаданных и содержимого можно восстановить.",
                    d.incremental.max(d.old_versions.len() as u32)
                )
            } else {
                format!(
                    "Документ хранит историю сохранений ({}): прежние авторы и пути к файлам.",
                    ru_n(d.old_versions.len(), "версия", "версии", "версий")
                )
            };
            f.recommendation = "Пересохранять PDF полностью («Сохранить как» с оптимизацией) или очищать скрытые данные перед публикацией.";
            f.evidence = d.old_versions.join("\n");
            f.docs = vec![d.id];
            f.people = d.people.clone();
            f.fields = vec!["incremental_updates".into(), "old_versions".into()];
            drafts.push(f);
        }
        if d.gps.is_some() {
            gps_docs.push(d);
        }
        if d.thumb_diff {
            let mut f = Draft::new(
                "thumbnail",
                d.key.clone(),
                format!("Миниатюра EXIF может отличаться от фото ({})", d.name),
                Severity::Medium,
            );
            f.mitre = "T1591 · Gather Victim Org Information";
            f.cvss = Some(5.3);
            f.description = "Фото отредактировано в графическом редакторе, но встроенная миниатюра EXIF сохранена: она может показывать исходный (необрезанный, незамазанный) кадр.".into();
            f.recommendation =
                "Удалять EXIF и миниатюры перед публикацией; сравнить миниатюру с изображением.";
            f.evidence = format!(
                "{}\nПО: {}",
                d.camera.as_deref().unwrap_or("камера неизвестна"),
                d.software.join(", ")
            );
            f.docs = vec![d.id];
            f.people = d.people.clone();
            f.fields = vec!["thumbnail".into()];
            drafts.push(f);
        }
        if d.has_macros {
            let mut f = Draft::new(
                "macros",
                d.key.clone(),
                format!("Документ с макросами VBA: {}", d.name),
                Severity::Medium,
            );
            f.mitre = "T1059.005 · Command and Scripting Interpreter: Visual Basic";
            f.cvss = Some(4.3);
            f.description = "Опубликованный документ содержит проект VBA: исходный код макросов раскрывает внутреннюю логику, пути и иногда учётные данные; такие файлы приучают пользователей включать макросы.".into();
            f.recommendation =
                "Не публиковать документы с макросами; проверить код макросов на секреты и пути.";
            f.evidence = if d.macros.is_empty() {
                "vbaProject.bin".into()
            } else {
                format!("Модули: {}", d.macros.join(", "))
            };
            f.docs = vec![d.id];
            f.people = d.people.clone();
            f.fields = vec!["has_macros".into()];
            drafts.push(f);
        }
        if !d.hidden_sheets.is_empty() {
            let sensitive = d.hidden_sheets.iter().any(|s| {
                let l = s.to_lowercase();
                SENSITIVE_SHEETS.iter().any(|k| l.contains(k))
            });
            let mut f = Draft::new(
                "hidden-sheets",
                d.key.clone(),
                format!("Скрытые листы в {}: {}", d.name, d.hidden_sheets.join(", ")),
                if sensitive {
                    Severity::Medium
                } else {
                    Severity::Low
                },
            );
            f.mitre = "T1213 · Data from Information Repositories";
            f.description = "Книга содержит скрытые листы: они не видны при просмотре, но доступны любому, кто откроет файл.".into();
            f.recommendation = "Удалять служебные листы перед публикацией, а не скрывать их.";
            f.evidence = d.hidden_sheets.join("\n");
            f.docs = vec![d.id];
            f.people = d.people.clone();
            f.fields = vec!["hidden_sheets".into()];
            drafts.push(f);
        }
        if d.has_js {
            let mut f = Draft::new(
                "pdf-javascript",
                d.key.clone(),
                format!("PDF содержит JavaScript: {}", d.name),
                Severity::Medium,
            );
            f.mitre = "T1204.002 · User Execution: Malicious File";
            f.description = "В PDF есть действия JavaScript. В опубликованном документе компании это нетипично и может указывать на компрометацию или трекинг.".into();
            f.recommendation = "Проверить сценарий, пересоздать документ без JavaScript.";
            f.docs = vec![d.id];
            f.fields = vec!["has_javascript".into()];
            drafts.push(f);
        }
    }
    if !gps_docs.is_empty() {
        let mut f = Draft::new(
            "gps",
            "project",
            format!("GPS-координаты в {} фото", gps_docs.len()),
            Severity::Medium,
        );
        f.source = "EXIF";
        f.mitre = "T1591.001 · Gather Victim Org Information: Determine Physical Locations";
        f.cvss = Some(4.3);
        f.description = "Опубликованные фото содержат координаты съёмки и модель устройства: раскрываются расположение объектов и устройства сотрудников.".into();
        f.recommendation = "Удалять EXIF перед публикацией, настроить CMS на автоматическую очистку метаданных изображений.";
        f.evidence = gps_docs
            .iter()
            .take(5)
            .map(|d| {
                let (la, lo) = d.gps.unwrap_or((0.0, 0.0));
                format!(
                    "{}: {la:.5}, {lo:.5} · {}",
                    d.name,
                    d.camera.as_deref().unwrap_or("-")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        f.docs = gps_docs.iter().map(|d| d.id).collect();
        f.people = top_people(&gps_docs, 3);
        f.fields = vec!["gps".into()];
        drafts.push(f);
    }

    // People.
    let humans: Vec<&Person> = ctx.people.iter().filter(|p| !p.service).collect();
    if humans.len() >= 5 {
        let mut f = Draft::new(
            "mass-names",
            "project",
            format!(
                "Раскрыты имена и логины {}",
                ru_n(humans.len(), "сотрудника", "сотрудников", "сотрудников")
            ),
            if humans.len() >= 20 {
                Severity::Medium
            } else {
                Severity::Low
            },
        );
        f.category = "people";
        f.source = "Люди и e-mail";
        f.module = "analysis";
        f.mitre = "T1589.003 · Gather Victim Identity Information: Employee Names";
        f.description = format!(
            "Метаданные документов раскрывают {} (ФИО и логины). Это основа для целевого фишинга и подбора паролей.",
            ru_n(humans.len(), "сотрудника", "сотрудников", "сотрудников")
        );
        f.recommendation = "Очищать поля Author/LastModifiedBy при публикации; задать нейтральное имя автора в шаблонах.";
        f.evidence = humans
            .iter()
            .take(8)
            .map(|p| format!("{} - {}", p.login, p.name))
            .collect::<Vec<_>>()
            .join("\n");
        f.people = humans.iter().take(20).map(|p| p.login.clone()).collect();
        drafts.push(f);
    }
    let svc: Vec<&Person> = ctx.people.iter().filter(|p| p.service).collect();
    if !svc.is_empty() {
        let mut f = Draft::new(
            "service-accounts",
            "project",
            format!(
                "Служебные учётные записи в метаданных: {}",
                svc.iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Severity::Info,
        );
        f.category = "people";
        f.source = "Люди и e-mail";
        f.module = "analysis";
        f.mitre = "T1087 · Account Discovery";
        f.description = "Документы созданы под общими учётными записями (Administrator, User…): возможна работа с правами администратора и общие пароли.".into();
        f.recommendation = "Работать под персональными учётными записями без прав администратора.";
        f.evidence = svc
            .iter()
            .map(|p| format!("{} · документов: {}", p.name, p.docs))
            .collect::<Vec<_>>()
            .join("\n");
        f.people = svc.iter().map(|p| p.login.clone()).collect();
        drafts.push(f);
    }
    if let Some(p) = ctx.patterns.first().filter(|p| p.conf >= 60 && p.n >= 2) {
        let mut f = Draft::new(
            "email-pattern",
            p.domain.clone(),
            format!(
                "Определён шаблон корпоративных e-mail: {}@{}",
                p.p, p.domain
            ),
            Severity::Info,
        );
        f.category = "people";
        f.source = "Люди и e-mail";
        f.module = "analysis";
        f.mitre = "T1589.002 · Gather Victim Identity Information: Email Addresses";
        f.description = format!(
            "По {} из документов определён шаблон {}@{} (уверенность {}%). Это упрощает подготовку целевого фишинга.",
            ru_n(p.n as usize, "адресу", "адресам", "адресам"),
            p.p,
            p.domain,
            p.conf
        );
        f.recommendation = "Учесть в программе обучения сотрудников; включить DMARC p=reject и защиту от спуфинга.";
        f.evidence = format!("Пример: {}", p.ex);
        f.host = Some(p.domain.clone());
        drafts.push(f);
    }

    crate::forensic::drafts(&an, &mut drafts);

    finalize(drafts, ctx, &by_id)
}

fn finalize(drafts: Vec<Draft>, ctx: &Ctx, by_id: &BTreeMap<u64, &DocFacts>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for d in drafts {
        let id = finding_id(d.rule, &d.key);
        if out.iter().any(|f| f.id == id) {
            continue;
        }
        // Every rule's severity label matches its CVSS band (one mapping, checked by every
        // analysis test in debug builds).
        debug_assert!(
            d.cvss.is_none_or(|c| super::draft::cvss_band(c) == d.sev),
            "{}: severity {:?} does not match CVSS {:?}",
            d.rule,
            d.sev,
            d.cvss
        );
        let doc = d.docs.first().copied();
        let dfacts = doc.and_then(|i| by_id.get(&i));
        let host = d
            .host
            .clone()
            .or_else(|| dfacts.map(|x| x.host.clone()).filter(|h| !h.is_empty()))
            .unwrap_or_else(|| "-".into());
        let first_doc_scan = d
            .docs
            .iter()
            .filter_map(|i| by_id.get(i).and_then(|x| x.first_scan.clone()))
            .min();
        let mut f = Finding {
            id,
            title: d.title,
            sev: d.sev,
            status: FindingStatus::New,
            host,
            category: d.category.into(),
            source: d.source.into(),
            module: d.module.into(),
            active: false,
            time: ctx.now.to_string(),
            first_scan: first_doc_scan.or_else(|| ctx.prev.scan_id.clone()),
            fixed_scan: None,
            tags: d.tags.iter().map(|s| s.to_string()).collect(),
            cve: vec![],
            cvss: d.cvss,
            mitre: d.mitre.into(),
            description: d.description,
            recommendation: d.recommendation.into(),
            evidence: d.evidence,
            request: String::new(),
            url: dfacts.and_then(|x| x.url.clone()),
            doc,
            notes: vec![],
            photos: vec![],
            rel: FindingRel {
                people: uniq(d.people),
                pcs: uniq(d.pcs),
                docs: d.docs.clone(),
            },
            provenance: FindingProvenance {
                rule: d.rule.into(),
                fields: d.fields,
                docs: d.docs,
            },
        };
        if let Some(p) = ctx.prev.findings.get(&id) {
            f.status = match p.status {
                // Seen again, so the fix did not hold.
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
        out.push(f);
    }
    out.sort_by(|a, b| a.sev.cmp(&b.sev).then(a.title.cmp(&b.title)));
    out
}

/// Project risk level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// No data yet (no scans or documents).
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn label_ru(self) -> &'static str {
        match self {
            RiskLevel::None => "нет данных",
            RiskLevel::Low => "низкий",
            RiskLevel::Medium => "средний",
            RiskLevel::High => "высокий",
            RiskLevel::Critical => "критический",
        }
    }
}

/// Project risk; uses the same rule as `F.sel.risk()` in the UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Risk {
    pub score: Option<u8>,
    pub level: RiskLevel,
}

/// Tag of findings about hosts outside the project scope (e.g. third-party data on a shared
/// address). Such findings are environment context: shown, but not counted in the risk score.
pub const OUT_OF_SCOPE_TAG: &str = "out_of_scope";

/// Computes `100·(1 − Π(1 − wᵢ))` over active findings (false positives, fixed ones and findings
/// tagged [`OUT_OF_SCOPE_TAG`] are excluded) with weights crit .25, high .12, warn .05, low .02, info 0. Levels: ≥ 90
/// critical, ≥ 70 high, ≥ 40 medium, otherwise low; `has_data = false` yields "no data".
pub fn risk(findings: &[Finding], has_data: bool) -> Risk {
    if !has_data {
        return Risk::default();
    }
    let p: f64 = findings
        .iter()
        .filter(|f| {
            !matches!(
                f.status,
                FindingStatus::FalsePositive | FindingStatus::Fixed
            ) && !f.tags.iter().any(|t| t == OUT_OF_SCOPE_TAG)
        })
        .map(|f| match f.sev {
            Severity::Critical => 0.25,
            Severity::High => 0.12,
            Severity::Medium => 0.05,
            Severity::Low => 0.02,
            Severity::Info => 0.0,
        })
        .fold(1.0, |acc, w| acc * (1.0 - w));
    let score = (100.0 * (1.0 - p)).round().clamp(0.0, 100.0) as u8;
    let level = match score {
        90..=100 => RiskLevel::Critical,
        70..=89 => RiskLevel::High,
        40..=69 => RiskLevel::Medium,
        _ => RiskLevel::Low,
    };
    Risk {
        score: Some(score),
        level,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(sev: Severity, status: FindingStatus) -> Finding {
        Finding {
            id: 1,
            title: String::new(),
            sev,
            status,
            host: "-".into(),
            category: "docs".into(),
            source: String::new(),
            module: String::new(),
            active: false,
            time: String::new(),
            first_scan: None,
            fixed_scan: None,
            tags: vec![],
            cve: vec![],
            cvss: None,
            mitre: String::new(),
            description: String::new(),
            recommendation: String::new(),
            evidence: String::new(),
            request: String::new(),
            url: None,
            doc: None,
            notes: vec![],
            photos: vec![],
            rel: FindingRel::default(),
            provenance: FindingProvenance::default(),
        }
    }

    #[test]
    fn risk_rules() {
        assert_eq!(risk(&[], false).level, RiskLevel::None);
        assert_eq!(
            risk(&[], true),
            Risk {
                score: Some(0),
                level: RiskLevel::Low
            }
        );
        let one = risk(&[f(Severity::Critical, FindingStatus::New)], true);
        assert_eq!(one.score, Some(25));
        // False positives and fixed findings do not count.
        let r = risk(
            &[
                f(Severity::Critical, FindingStatus::FalsePositive),
                f(Severity::Critical, FindingStatus::Fixed),
                f(Severity::Low, FindingStatus::Accepted),
            ],
            true,
        );
        assert_eq!(r.score, Some(2));
        // Out-of-scope context does not raise the scope risk.
        let mut oos = f(Severity::Critical, FindingStatus::New);
        oos.tags.push(OUT_OF_SCOPE_TAG.into());
        assert_eq!(risk(&[oos], true).score, Some(0));
        let many: Vec<Finding> = (0..8)
            .map(|_| f(Severity::Critical, FindingStatus::Confirmed))
            .collect();
        assert_eq!(risk(&many, true).level, RiskLevel::Critical);
        let some: Vec<Finding> = (0..4)
            .map(|_| f(Severity::Critical, FindingStatus::New))
            .collect();
        assert_eq!(risk(&some, true).level, RiskLevel::Medium);
        assert_eq!(RiskLevel::High.label_ru(), "высокий");
        assert_ne!(finding_id("macros", "a"), finding_id("macros", "b"));
        assert_eq!(finding_id("macros", "a"), finding_id("macros", "a"));
    }
}

#[cfg(test)]
mod plural_tests {
    use super::*;

    #[test]
    fn ru_plural_and_sw_label() {
        let d = |n| ru_n(n, "документ", "документа", "документов");
        assert_eq!(
            [d(1), d(2), d(5), d(11), d(21), d(22), d(112)],
            [
                "1 документ",
                "2 документа",
                "5 документов",
                "11 документов",
                "21 документ",
                "22 документа",
                "112 документов"
            ]
        );
        assert_eq!(
            sw_label("Acrobat Distiller 5.0.5", "5.0.5"),
            "Acrobat Distiller 5.0.5"
        );
        assert_eq!(
            sw_label("Microsoft Word 2010", "14"),
            "Microsoft Word 2010 (14)"
        );
    }
}
