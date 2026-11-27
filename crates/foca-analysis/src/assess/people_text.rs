//! People whose contacts or personal identifiers are written next to their names in published
//! documents: one aggregated finding per project (phones, e-mails, identifiers).

use foca_core::Severity;

use super::draft::Draft;
use foca_core::api::Person;

/// Identifier kinds that are personal data on their own (not contact channels).
fn personal_id(kind: &str) -> bool {
    !matches!(kind, "edrpou" | "address")
}

/// Adds the `people.text_contacts` finding when at least one person named in document text has a
/// phone, a personal e-mail or an identifier next to the name. PII alone is Medium; identifier
/// values themselves get their own per-document PII findings.
pub(crate) fn drafts(people: &[Person], out: &mut Vec<Draft>) {
    let exposed: Vec<&Person> = people
        .iter()
        .filter(|p| !p.service)
        .filter(|p| {
            !p.phones.is_empty()
                || p.ids.iter().any(|k| personal_id(k))
                || (p.src_kind == "text" && !p.emails.is_empty())
        })
        .collect();
    if exposed.is_empty() {
        return;
    }
    let with_phone = exposed.iter().filter(|p| !p.phones.is_empty()).count();
    let with_mail = exposed.iter().filter(|p| !p.emails.is_empty()).count();
    let with_id = exposed
        .iter()
        .filter(|p| p.ids.iter().any(|k| personal_id(k)))
        .count();
    let mut docs: Vec<u64> = exposed.iter().filter_map(|p| p.src_doc).collect();
    docs.sort_unstable();
    docs.dedup();
    let mut f = Draft::new(
        "people.text_contacts",
        "project",
        format!(
            "Контакты людей в тексте документов: {}",
            people_n(exposed.len())
        ),
        Severity::Medium,
    );
    f.source = "Люди из текста документов";
    f.module = "people";
    f.category = "people";
    f.mitre = "T1589.003 · Gather Victim Identity Information: Employee Names";
    f.cvss = Some(super::draft::band_cvss(Severity::Medium));
    f.description = format!(
        "Рядом с именами в опубликованных документах указаны контакты: телефон: {with_phone}, e-mail: {with_mail}, личные идентификаторы: {with_id}. Такие данные используют для фишинга и социальной инженерии; значения телефонов и идентификаторов хранятся только в виде масок."
    );
    f.recommendation = "Убрать личные контакты и идентификаторы из публикуемых документов (оставить общие контакты подразделений), обезличить списки людей; предупредить сотрудников о целевом фишинге.";
    f.evidence = exposed
        .iter()
        .take(10)
        .map(|p| {
            let mut parts: Vec<String> = Vec::new();
            if let Some(t) = &p.title {
                parts.push(t.clone());
            }
            parts.extend(p.phones.iter().take(2).cloned());
            if !p.ids.is_empty() {
                parts.push(p.ids.join(", "));
            }
            format!("{}: {}", p.name, parts.join("; "))
        })
        .collect::<Vec<_>>()
        .join("\n");
    f.docs = docs;
    f.people = exposed.iter().map(|p| p.login.clone()).collect();
    f.fields = vec!["text".into()];
    f.tags = vec!["pii"];
    out.push(f);
}

/// "N человек" with the Russian plural (the finding text is matched by the translation catalog).
fn people_n(n: usize) -> String {
    let w = match (n % 10, n % 100) {
        (_, 11..=14) => "человек",
        (2..=4, _) => "человека",
        _ => "человек",
    };
    format!("{n} {w}")
}
