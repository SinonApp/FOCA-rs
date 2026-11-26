//! AI summary texts: prompt wording per language, redaction placeholders and their reversal,
//! and the stored summary history of a project.

use foca_core::Lang;
use serde_json::{json, Value};

/// Redaction placeholders sent to the provider. They are language-neutral on purpose: a model
/// keeps ASCII tokens intact, while a Cyrillic word in brackets may get inflected.
pub(crate) const TAG_SECRET: &str = "SECRET";
pub(crate) const TAG_EMAIL: &str = "EMAIL";
pub(crate) const TAG_NAME: &str = "NAME";
pub(crate) const TAG_CLIENT: &str = "CLIENT";
pub(crate) const TAG_CLIENT_DOMAIN: &str = "CLIENT-DOMAIN";
pub(crate) const TAG_INTERNAL_IP: &str = "INTERNAL-IP";
/// Keys of `ai_preview.marks` (the domain placeholder counts as `CLIENT`).
pub(crate) const MARK_KEYS: [&str; 5] =
    [TAG_SECRET, TAG_EMAIL, TAG_NAME, TAG_CLIENT, TAG_INTERNAL_IP];

/// Placeholders written up to 2.0.0-beta.2 (Russian words), kept for reversal of
/// summaries stored by them.
const LEGACY_CLIENT: &str = "[КЛИЕНТ]";
const LEGACY_CLIENT_DOMAIN: &str = "[КЛИЕНТ-ДОМЕН]";

/// Puts the client name and domain back into a summary (new and legacy placeholders). Secrets,
/// names and e-mails stay redacted: several values share one placeholder, so they cannot be
/// restored and must not reach a report anyway.
pub(crate) fn unredact_client(text: &str, client: &str, domain: &str) -> String {
    let mut out = text.to_string();
    if !domain.is_empty() {
        for tag in [
            format!("[{TAG_CLIENT_DOMAIN}]"),
            LEGACY_CLIENT_DOMAIN.to_string(),
        ] {
            out = out.replace(&tag, domain);
        }
    }
    let client = if client.is_empty() { domain } else { client };
    if !client.is_empty() {
        for tag in [format!("[{TAG_CLIENT}]"), LEGACY_CLIENT.to_string()] {
            out = out.replace(&tag, client);
        }
    }
    out
}

/// Fixed wording of the prompt in one language.
pub(crate) struct PromptText {
    pub system: &'static str,
    pub project: &'static str,
    pub domain: &'static str,
    /// `{date}`, `{profile}`, `{active}`, `{docs}`, `{hosts}`, `{people}`.
    pub scan: &'static str,
    pub active: &'static str,
    pub no_scans: &'static str,
    pub top: &'static str,
    pub no_top: &'static str,
    pub many_hosts: &'static str,
    pub medium: &'static str,
    pub people: &'static str,
    pub internal: &'static str,
    pub evidence: &'static str,
    pub task: &'static str,
}

const RU: PromptText = PromptText {
    system: "Ты аналитик информационной безопасности. Отвечай на русском языке, в Markdown с \
             разделами «## Ключевые риски» и «## Рекомендации». Метки в квадратных скобках \
             ([CLIENT], [SECRET] и другие) оставляй как есть.",
    project: "Проект",
    domain: "домен",
    scan: "Скан {date}, профиль «{profile}»{active}. Документов: {docs}, хостов: {hosts}, людей: {people}.",
    active: " (активный)",
    no_scans: "Сканов ещё не было.",
    top: "Находки (критичные и высокие):",
    no_top: "Критичных и высоких находок нет.",
    many_hosts: "несколько хостов",
    medium: "Средние",
    people: "Люди",
    internal: "Внутренние имена",
    evidence: "Доказательство",
    task: "Задача: кратко опиши ключевые риски и дай приоритетные рекомендации. Пиши на русском языке.",
};

const UK: PromptText = PromptText {
    system: "Ти аналітик з інформаційної безпеки. Відповідай українською мовою, у Markdown з \
             розділами «## Ключові ризики» і «## Рекомендації». Мітки у квадратних дужках \
             ([CLIENT], [SECRET] та інші) залишай без змін.",
    project: "Проєкт",
    domain: "домен",
    scan: "Скан {date}, профіль «{profile}»{active}. Документів: {docs}, хостів: {hosts}, людей: {people}.",
    active: " (активний)",
    no_scans: "Сканувань ще не було.",
    top: "Знахідки (критичні та високі):",
    no_top: "Критичних і високих знахідок немає.",
    many_hosts: "кілька хостів",
    medium: "Середні",
    people: "Люди",
    internal: "Внутрішні імена",
    evidence: "Доказ",
    task: "Завдання: стисло опиши ключові ризики й дай пріоритетні рекомендації. Пиши українською мовою.",
};

const EN: PromptText = PromptText {
    system: "You are an information security analyst. Answer in English, in Markdown with the \
             sections \"## Key risks\" and \"## Recommendations\". Keep the placeholders in square \
             brackets ([CLIENT], [SECRET] and others) unchanged.",
    project: "Project",
    domain: "domain",
    scan: "Scan {date}, profile \"{profile}\"{active}. Documents: {docs}, hosts: {hosts}, people: {people}.",
    active: " (active)",
    no_scans: "No scans yet.",
    top: "Findings (critical and high):",
    no_top: "No critical or high findings.",
    many_hosts: "several hosts",
    medium: "Medium",
    people: "People",
    internal: "Internal names",
    evidence: "Evidence",
    task: "Task: briefly describe the key risks and give prioritized recommendations. Write in English.",
};

pub(crate) fn prompt_text(lang: Lang) -> &'static PromptText {
    match lang {
        Lang::Ru => &RU,
        Lang::Uk => &UK,
        Lang::En => &EN,
    }
}

/// Translates a finding title for the prompt (engine texts are Russian; the report catalog
/// covers them in EN/UK).
pub(crate) fn finding_title(title: &str, rule: &str, lang: Lang) -> String {
    #[cfg(feature = "report")]
    {
        foca_report::translate_finding_text(title, rule, lang)
    }
    #[cfg(not(feature = "report"))]
    {
        let _ = (rule, lang);
        title.to_string()
    }
}

/// Client name and domain of a project as the AI preview redacts them.
pub(crate) fn client_and_domain(snap: &foca_core::api::Snapshot) -> (String, String) {
    let dom = if snap.project.domain.is_empty() {
        snap.project.name.clone()
    } else {
        snap.project.domain.clone()
    };
    let client = if snap.scope.client.is_empty() {
        snap.project.client.clone()
    } else {
        snap.scope.client.clone()
    };
    (client, dom)
}

// ---------- summary history ----------

/// Project setting with every stored summary, newest first.
pub(crate) const AI_HISTORY_KEY: &str = "ai_summaries";
/// Most summaries kept per project; the oldest go first.
pub(crate) const AI_HISTORY_MAX: usize = 50;

/// Stored history plus the summary that releases before the history wrote alone into
/// `ai_summary` (it becomes the first entry, id `ai-legacy`).
pub(crate) fn history_with_legacy(list: Option<Value>, legacy: Option<&Value>) -> Vec<Value> {
    if let Some(Value::Array(items)) = list {
        return items;
    }
    match legacy {
        Some(v) if v["text"].as_str().is_some_and(|t| !t.trim().is_empty()) => {
            let mut e = v.clone();
            if e["id"].as_str().is_none_or(str::is_empty) {
                e["id"] = json!("ai-legacy");
            }
            vec![e]
        }
        _ => Vec::new(),
    }
}

/// Id of a new summary, unique within the history (equal answers in the same second differ).
pub(crate) fn new_summary_id(items: &[Value], created: &str, text: &str) -> String {
    let mut n = items.len();
    loop {
        let id = format!(
            "ai-{}",
            crate::util::base36(crate::util::fnv(&format!("{created}|{n}|{text}")) as u64)
        );
        if !items.iter().any(|e| e["id"].as_str() == Some(id.as_str())) {
            return id;
        }
        n += 1;
    }
}

/// Adds a summary in front and drops the oldest beyond [`AI_HISTORY_MAX`].
pub(crate) fn history_push(items: &mut Vec<Value>, entry: Value) {
    items.insert(0, entry);
    items.truncate(AI_HISTORY_MAX);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unredact_restores_new_and_legacy_client_tags() {
        let s = "[CLIENT] on [CLIENT-DOMAIN]; old: [КЛИЕНТ], [КЛИЕНТ-ДОМЕН]; [SECRET] [NAME]";
        let r = unredact_client(s, "ТОВ «Приклад»", "example.test");
        assert_eq!(
            r,
            "ТОВ «Приклад» on example.test; old: ТОВ «Приклад», example.test; [SECRET] [NAME]"
        );
        // no client name: the domain stands in for it
        assert_eq!(unredact_client("[CLIENT]", "", "a.test"), "a.test");
        assert_eq!(unredact_client("[CLIENT]", "", ""), "[CLIENT]");
    }

    #[test]
    fn prompt_wording_has_no_foreign_language_in_uk_and_en() {
        let cyr = |s: &str| s.chars().any(|c| matches!(c, '\u{0400}'..='\u{04FF}'));
        let ru_only = |s: &str| s.chars().any(|c| "ыэъёЫЭЪЁ".contains(c));
        for t in [&UK, &EN] {
            let all = [
                t.system,
                t.project,
                t.domain,
                t.scan,
                t.active,
                t.no_scans,
                t.top,
                t.no_top,
                t.many_hosts,
                t.medium,
                t.people,
                t.internal,
                t.evidence,
                t.task,
            ];
            for s in all {
                assert!(!ru_only(s), "{s}");
                if std::ptr::eq(t, &EN) {
                    assert!(!cyr(s), "{s}");
                }
            }
        }
        assert!(UK.task.contains("українською"));
        assert!(EN.system.contains("in English"));
        assert!(RU.task.contains("на русском"));
    }

    #[test]
    fn legacy_summary_becomes_the_first_history_entry() {
        let legacy = json!({ "text": "## Риски", "provider": "deepseek", "model": "m", "created": "2026-01-01T00:00:00Z" });
        let h = history_with_legacy(None, Some(&legacy));
        assert_eq!(h.len(), 1);
        assert_eq!(h[0]["id"], "ai-legacy");
        assert_eq!(h[0]["model"], "m");
        // an existing history wins over the legacy key
        let h = history_with_legacy(Some(json!([])), Some(&legacy));
        assert!(h.is_empty());
        assert!(history_with_legacy(None, Some(&json!({ "text": " " }))).is_empty());
        let mut items = Vec::new();
        for i in 0..(AI_HISTORY_MAX + 3) {
            history_push(&mut items, json!({ "id": i }));
        }
        assert_eq!(items.len(), AI_HISTORY_MAX);
        let a = new_summary_id(&[], "t", "same");
        let b = new_summary_id(&[json!({ "id": a })], "t", "same");
        assert_ne!(a, b);
        assert_eq!(items[0]["id"], AI_HISTORY_MAX + 2);
    }
}
