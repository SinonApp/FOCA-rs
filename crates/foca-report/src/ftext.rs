//! Finding texts in the report language loaded from `locales/{en,ru,uk}/findings.json`.
//!
//! The core (analysis, recon, network, ports) writes titles, descriptions, recommendations and
//! evidence in Russian; this module translates them to Ukrainian or English by finding rule
//! (`provenance.rule`) and a template of the Russian text with placeholders.
//!
//! Russian template: `{}` matches any fragment (data such as names, hosts, versions), `{n}` a
//! number, `{w}` a single word (the noun form picked by pluralization). Translation: `{0}`
//! inserts the fragment as is, `{0!}` translates the fragment too (nested core text such as a
//! secret name or port risk), `{0:one|few|many}` renders the number with the correctly
//! inflected noun. If no template of the rule matches, the original text is kept so no data
//! is lost; multi-line text is additionally translated line by line.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use foca_core::api::Finding;
use serde::Deserialize;

use crate::Lang;

#[derive(Debug, Deserialize)]
struct CatalogEntry {
    #[cfg_attr(not(test), allow(dead_code))]
    id: String,
    rules: String,
    pattern: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct FindingsLocale {
    catalog: Vec<CatalogEntry>,
    tech_cats: BTreeMap<String, String>,
    roles: BTreeMap<String, String>,
    terms: Vec<[String; 2]>,
    log_terms: Vec<[String; 2]>,
    scope_labels: BTreeMap<String, String>,
    log_notes: BTreeMap<String, String>,
}

fn locale_data(lang: Lang) -> &'static FindingsLocale {
    static EN: OnceLock<FindingsLocale> = OnceLock::new();
    static RU: OnceLock<FindingsLocale> = OnceLock::new();
    static UK: OnceLock<FindingsLocale> = OnceLock::new();
    match lang {
        Lang::En => EN.get_or_init(|| {
            serde_json::from_str(include_str!("../../../locales/en/findings.json"))
                .expect("valid locales/en/findings.json")
        }),
        Lang::Ru => RU.get_or_init(|| {
            serde_json::from_str(include_str!("../../../locales/ru/findings.json"))
                .expect("valid locales/ru/findings.json")
        }),
        Lang::Uk => UK.get_or_init(|| {
            serde_json::from_str(include_str!("../../../locales/uk/findings.json"))
                .expect("valid locales/uk/findings.json")
        }),
    }
}

/// Returns a person or host role in the report language (unknown roles as is).
pub fn role(r: &str, lang: Lang) -> String {
    locale_data(lang)
        .roles
        .get(r)
        .cloned()
        .unwrap_or_else(|| r.to_string())
}

/// Returns the host scope status (`Host.scope`: `in_scope` | `out_of_scope` | `excluded`) in
/// the report language; empty or unknown gives a dash.
pub fn scope_label(code: &str, lang: Lang) -> String {
    locale_data(lang)
        .scope_labels
        .get(code)
        .cloned()
        .unwrap_or_else(|| "-".into())
}

/// Returns a technology category in the report language (unknown categories as is).
pub fn tech_category(cat: &str, lang: Lang) -> String {
    locale_data(lang)
        .tech_cats
        .get(cat)
        .cloned()
        .unwrap_or_else(|| cat.to_string())
}

/// Translates a technology's outdated note (a version comparison or the rule's EOL text).
pub fn outdated_note(s: &str, lang: Lang) -> String {
    translate(s, "recon.outdated_tech", lang)
}

/// Translates a request log error or address into the report language using `log_terms`.
/// The error code before the colon (`network:`, `timeout:`) is kept; a repeated code is
/// collapsed in English.
pub fn log_text(s: &str, lang: Lang) -> String {
    if lang == Lang::Ru || s.is_empty() {
        return s.to_string();
    }
    let mut out = s.to_string();
    for [ru, tr] in &locale_data(lang).log_terms {
        if out.contains(ru.as_str()) {
            out = out.replace(ru.as_str(), tr.as_str());
        }
    }
    for code in ["network", "timeout", "proxy"] {
        out = out.replace(&format!("{code}: {code}: "), &format!("{code}: "));
        if out == format!("{code}: {code}") {
            out = code.to_string();
        }
    }
    out
}

/// Translates a log response note (brute force) into the report language; unknown notes as
/// is.
pub fn log_note(code: &str, lang: Lang) -> String {
    locale_data(lang)
        .log_notes
        .get(code)
        .cloned()
        .unwrap_or_else(|| code.to_string())
}

/// Builds the log error cell: the module note (soft-404, …) and the error text in the report
/// language.
pub fn log_error_cell(note: Option<&str>, error: Option<&str>, lang: Lang) -> String {
    let n = note.filter(|x| !x.is_empty()).map(|x| log_note(x, lang));
    let e = error.filter(|x| !x.is_empty()).map(|x| log_text(x, lang));
    match (n, e) {
        (Some(n), Some(e)) => format!("{n} · {e}"),
        (Some(x), None) | (None, Some(x)) => x,
        _ => String::new(),
    }
}

/// Builds the log size/type cell, e.g. `5 KB · text/html`; empty if nothing is known.
pub fn log_size_type(bytes: u64, ctype: Option<&str>, lang: Lang) -> String {
    let (kb, mb) = if lang == Lang::En {
        ("KB", "MB")
    } else {
        ("КБ", "МБ")
    };
    let size = match bytes {
        0 => String::new(),
        n if n >= 1024 * 1024 => format!("{:.1} {mb}", n as f64 / 1048576.0),
        n => format!("{} {kb}", n.div_ceil(1024)),
    };
    let ct = ctype
        .map(|c| c.split(';').next().unwrap_or("").trim().to_string())
        .unwrap_or_default();
    match (size.is_empty(), ct.is_empty()) {
        (false, false) => format!("{size} · {ct}"),
        (false, true) => size,
        (true, false) => ct,
        _ => String::new(),
    }
}

/// Replaces known core data fragments (see `terms` in `findings.json`).
pub fn terms(s: &str, lang: Lang) -> String {
    if lang == Lang::Ru {
        return s.to_string();
    }
    let mut out = s.to_string();
    for [ru, tr] in &locale_data(lang).terms {
        if out.contains(ru.as_str()) {
            out = out.replace(ru.as_str(), tr.as_str());
        }
    }
    out
}

/// Translates one finding field. `rule` is `provenance.rule`.
pub fn translate(text: &str, rule: &str, lang: Lang) -> String {
    if lang == Lang::Ru || text.is_empty() {
        return text.to_string();
    }
    if let Some(t) = tr_whole(text, rule, lang, 0) {
        return t;
    }
    text.split('\n')
        .map(|l| {
            tr_whole(l, rule, lang, 0)
                .or_else(|| tr_sentences(l, rule, lang))
                .unwrap_or_else(|| l.to_string())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Most sentence boundaries tried in one line (keeps the quadratic search small).
const MAX_SENTENCES: usize = 40;

/// Translates a line sentence by sentence when no template covers it whole (the core appends
/// notes such as the out-of-scope caveat to a templated description). Takes the longest
/// translatable run of sentences first; an unknown sentence is kept as is. `None` if nothing
/// matched.
fn tr_sentences(line: &str, rule: &str, lang: Lang) -> Option<String> {
    let b = line.as_bytes();
    let cuts: Vec<usize> = (0..b.len())
        .filter(|&i| matches!(b[i], b'.' | b'!' | b'?') && (i + 1 == b.len() || b[i + 1] == b' '))
        .map(|i| i + 1)
        .chain(std::iter::once(b.len()))
        .collect();
    if cuts.len() < 2 || cuts.len() > MAX_SENTENCES {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    let mut hit = false;
    let mut pos = 0;
    while pos < b.len() {
        let next: Vec<usize> = cuts.iter().copied().filter(|&c| c > pos).collect();
        let found = next.iter().rev().find_map(|&c| {
            let seg = line[pos..c].trim();
            tr_whole(seg, rule, lang, 0).map(|t| (c, t))
        });
        let (end, seg) = match found {
            Some((c, t)) => {
                hit = true;
                (c, t)
            }
            None => (next[0], line[pos..next[0]].trim().to_string()),
        };
        if !seg.is_empty() {
            out.push(seg);
        }
        pos = end;
        while pos < b.len() && b[pos] == b' ' {
            pos += 1;
        }
    }
    hit.then(|| out.join(" "))
}

/// Returns the finding with title, description, recommendation and evidence in the report
/// language.
pub fn localize(f: &Finding, lang: Lang) -> Finding {
    let mut f = f.clone();
    if lang == Lang::Ru {
        return f;
    }
    let rule = f.provenance.rule.clone();
    f.title = translate(&f.title, &rule, lang);
    f.description = translate(&f.description, &rule, lang);
    f.recommendation = translate(&f.recommendation, &rule, lang);
    f.evidence = translate(&f.evidence, &rule, lang);
    f.provenance.fields = f
        .provenance
        .fields
        .iter()
        .map(|x| translate(x, "secret", lang))
        .collect();
    for t in [&mut f.title, &mut f.description, &mut f.evidence] {
        *t = terms(t, lang);
    }
    f
}

fn rule_matches(spec: &str, rule: &str) -> bool {
    spec.split(',').any(|s| {
        let s = s.trim();
        s == "*" || s == rule || s.strip_suffix('*').is_some_and(|p| rule.starts_with(p))
    })
}

fn tr_whole(text: &str, rule: &str, lang: Lang, depth: u8) -> Option<String> {
    if depth > 2 {
        return None;
    }
    for e in &locale_data(lang).catalog {
        if !rule_matches(&e.rules, rule) {
            continue;
        }
        if let Some(caps) = capture(&e.pattern, text) {
            return Some(render(&e.text, &caps, rule, lang, depth));
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Tok<'a> {
    Lit(&'a str),
    Any,
    Num,
    Word,
}

fn tokens(pat: &str) -> Vec<Tok<'_>> {
    let mut out = Vec::new();
    let mut rest = pat;
    while !rest.is_empty() {
        let next = ["{}", "{n}", "{w}"]
            .iter()
            .filter_map(|p| rest.find(p).map(|i| (i, *p)))
            .min_by_key(|(i, _)| *i);
        match next {
            Some((i, p)) => {
                if i > 0 {
                    out.push(Tok::Lit(&rest[..i]));
                }
                out.push(match p {
                    "{}" => Tok::Any,
                    "{n}" => Tok::Num,
                    _ => Tok::Word,
                });
                rest = &rest[i + p.len()..];
            }
            None => {
                out.push(Tok::Lit(rest));
                break;
            }
        }
    }
    out
}

/// Matches text against a Russian template and returns the captures (`{w}` is not
/// captured).
///
/// Backtracking over `{}` placeholders is memoized on (token index, byte offset): a
/// state that failed once fails again, so the search stays polynomial even for long
/// evidence strings and templates with many placeholders.
fn capture<'a>(pat: &str, text: &'a str) -> Option<Vec<&'a str>> {
    struct M<'t, 'a> {
        toks: &'t [Tok<'t>],
        text: &'a str,
        failed: std::collections::HashSet<(usize, usize)>,
        caps: Vec<&'a str>,
    }
    fn go(m: &mut M<'_, '_>, ti: usize, pos: usize) -> bool {
        let Some(t) = m.toks.get(ti).copied() else {
            return pos == m.text.len();
        };
        if m.failed.contains(&(ti, pos)) {
            return false;
        }
        let s = &m.text[pos..];
        let ok = match t {
            Tok::Lit(l) => s.starts_with(l) && go(m, ti + 1, pos + l.len()),
            Tok::Num | Tok::Word => {
                let end = s
                    .char_indices()
                    .find(|(_, c)| {
                        if t == Tok::Num {
                            !c.is_ascii_digit()
                        } else {
                            !c.is_alphabetic()
                        }
                    })
                    .map(|(i, _)| i)
                    .unwrap_or(s.len());
                if end == 0 {
                    false
                } else {
                    let n = m.caps.len();
                    if t == Tok::Num {
                        m.caps.push(&m.text[pos..pos + end]);
                    }
                    let ok = go(m, ti + 1, pos + end);
                    if !ok {
                        m.caps.truncate(n);
                    }
                    ok
                }
            }
            Tok::Any => {
                // A data fragment never spans lines (multi-line text is handled line by line).
                let line = s.find('\n').unwrap_or(s.len());
                let ends: Vec<usize> = s[..line]
                    .char_indices()
                    .map(|(i, _)| i)
                    .skip(1)
                    .chain(std::iter::once(line))
                    .collect();
                let mut ok = false;
                for e in ends {
                    let n = m.caps.len();
                    m.caps.push(&m.text[pos..pos + e]);
                    if go(m, ti + 1, pos + e) {
                        ok = true;
                        break;
                    }
                    m.caps.truncate(n);
                }
                ok
            }
        };
        if !ok {
            m.failed.insert((ti, pos));
        }
        ok
    }
    let toks = tokens(pat);
    let mut m = M {
        toks: &toks,
        text,
        failed: Default::default(),
        caps: Vec::new(),
    };
    go(&mut m, 0, 0).then_some(m.caps)
}

/// Picks the plural form: RU/UK use 1 / 2-4 / 5+ (11-14 take the "many" form), EN uses
/// 1 / other.
fn plural_form<'a>(n: u64, forms: &[&'a str], lang: Lang) -> &'a str {
    let pick = |i: usize| forms.get(i).or(forms.last()).copied().unwrap_or("");
    match lang {
        Lang::En => pick(if n == 1 { 0 } else { 2 }),
        _ => match (n % 10, n % 100) {
            (_, 11..=14) => pick(2),
            (1, _) => pick(0),
            (2..=4, _) => pick(1),
            _ => pick(2),
        },
    }
}

fn render(tpl: &str, caps: &[&str], rule: &str, lang: Lang, depth: u8) -> String {
    let mut out = String::new();
    let mut rest = tpl;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let Some(j) = after.find('}') else {
            out.push_str(&rest[i..]);
            return out;
        };
        let spec = &after[..j];
        let (idx, mode) = match spec.find([':', '!']) {
            Some(k) => (&spec[..k], &spec[k..]),
            None => (spec, ""),
        };
        match idx.parse::<usize>().ok().and_then(|n| caps.get(n)) {
            Some(v) if mode.is_empty() => out.push_str(v),
            Some(v) if mode == "!" => out.push_str(
                &tr_whole(v, rule, lang, depth + 1).unwrap_or_else(|| tech_category(v, lang)),
            ),
            Some(v) if mode.starts_with(':') => {
                let forms: Vec<&str> = mode[1..].split('|').collect();
                let n: u64 = v.parse().unwrap_or(0);
                out.push_str(&format!("{v} {}", plural_form(n, &forms, lang)));
            }
            _ => {
                out.push('{');
                out.push_str(spec);
                out.push('}');
            }
        }
        rest = &after[j + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn en(t: &str, rule: &str) -> String {
        translate(t, rule, Lang::En)
    }
    fn uk(t: &str, rule: &str) -> String {
        translate(t, rule, Lang::Uk)
    }

    #[test]
    fn capture_does_not_backtrack_exponentially() {
        // Many separators and no closing literal: naive backtracking over six `{}`
        // placeholders would try O(n^6) splits.
        let text = "a, ".repeat(400);
        let t = std::time::Instant::now();
        assert!(capture("{}, {}, {}, {}, {}, {}!", &text).is_none());
        let ok = capture("{}: {} / {}", "host: example.com / 443").unwrap();
        assert_eq!(ok, ["host", "example.com", "443"]);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn findings_locales_are_in_sync() {
        let ru = locale_data(Lang::Ru);
        let uk = locale_data(Lang::Uk);
        let en = locale_data(Lang::En);
        assert_eq!(ru.catalog.len(), uk.catalog.len());
        assert_eq!(ru.catalog.len(), en.catalog.len());
        for ((r, u), e) in ru
            .catalog
            .iter()
            .zip(uk.catalog.iter())
            .zip(en.catalog.iter())
        {
            assert_eq!(r.id, u.id);
            assert_eq!(r.id, e.id);
            assert_eq!(r.rules, u.rules);
            assert_eq!(r.rules, e.rules);
            assert_eq!(r.pattern, u.pattern);
            assert_eq!(r.pattern, e.pattern);
        }
        assert_eq!(
            ru.tech_cats.keys().collect::<Vec<_>>(),
            uk.tech_cats.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            ru.tech_cats.keys().collect::<Vec<_>>(),
            en.tech_cats.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            ru.roles.keys().collect::<Vec<_>>(),
            uk.roles.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            ru.roles.keys().collect::<Vec<_>>(),
            en.roles.keys().collect::<Vec<_>>()
        );
        assert_eq!(ru.terms.len(), uk.terms.len());
        assert_eq!(ru.terms.len(), en.terms.len());
        assert_eq!(ru.log_terms.len(), uk.log_terms.len());
        assert_eq!(ru.log_terms.len(), en.log_terms.len());
        assert_eq!(
            ru.scope_labels.keys().collect::<Vec<_>>(),
            uk.scope_labels.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            ru.scope_labels.keys().collect::<Vec<_>>(),
            en.scope_labels.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            ru.log_notes.keys().collect::<Vec<_>>(),
            uk.log_notes.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            ru.log_notes.keys().collect::<Vec<_>>(),
            en.log_notes.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn templates_with_plurals_and_nested() {
        assert_eq!(
            en("Adobe Photoshop 7.0 (EOL) у 3 документов", "eol-software"),
            "Adobe Photoshop 7.0 (EOL) in 3 documents"
        );
        assert_eq!(
            en("LibreOffice 7.2 (EOL) у 1 документа", "eol-software"),
            "LibreOffice 7.2 (EOL) in 1 document"
        );
        assert_eq!(
            uk("LibreOffice 7.2 (EOL) у 1 документа", "eol-software"),
            "LibreOffice 7.2 (EOL) у 1 документі"
        );
        assert_eq!(
            en("1 документ создан в Microsoft Word 2010 (14), поддержка завершена 2020-10-13. Это указывает на рабочие места с уязвимым ПО, пригодные для фишинга с вредоносными вложениями.", "eol-software"),
            "1 document was created in Microsoft Word 2010 (14); support ended 2020-10-13. This points to workstations with vulnerable software, suitable for phishing with malicious attachments."
        );
        assert_eq!(
            en("В публично доступном документе «a.docx» найден секрет (Пароль в строке подключения): текст, строка 4.", "secret"),
            "A secret (Password in a connection string) was found in the publicly available document «a.docx»: text, line 4."
        );
        assert_eq!(
            en("Порт 6379/tcp (Redis) на h.example (1.2.3.4) принимает соединения из интернета. Redis из интернета часто работает без пароля: чтение/запись данных и выполнение команд на сервере. Redis ответил на PING без пароля: авторизация не требуется.", "ports-exposed"),
            "Port 6379/tcp (Redis) on h.example (1.2.3.4) accepts connections from the internet. Internet-facing Redis often runs without a password: data read/write and command execution on the server. Redis answered PING without a password: no authentication is required."
        );
        assert_eq!(
            en("jQuery (JS-библиотека): версия 1.8.2 старее 3.5.0. Старые версии содержат публично известные уязвимости.", "recon.outdated_tech"),
            "jQuery (JS library): version 1.8.2 is older than 3.5.0. Old versions contain publicly known vulnerabilities."
        );
        // Line by line: known lines are translated, data stays.
        assert_eq!(
            en("Сигнатура: Word 2010\nДокументов: 2", "eol-software"),
            "Signature: Word 2010\nDocuments: 2"
        );
        // Unknown rule or text is kept as is.
        assert_eq!(en("Что-то новое", "unknown-rule"), "Что-то новое");
        assert_eq!(
            translate("Устаревшая ОС X у 2 документов", "eol-os", Lang::Ru),
            "Устаревшая ОС X у 2 документов"
        );
    }

    #[test]
    fn stage_1_4_findings_translate() {
        assert_eq!(
            en(
                "Дата создания позже даты изменения: «a.docx»",
                "doc.anomaly.created_after_modified"
            ),
            "Creation date is later than the modification date: «a.docx»"
        );
        assert_eq!(
            uk(
                "Возможно уязвимое ПО (CISA KEV): Microsoft Word 2013, сверьте версию",
                "sw.kev"
            ),
            "Можливо вразливе ПЗ (CISA KEV): Microsoft Word 2013, звірте версію"
        );
        assert_eq!(
            en(
                "Из документов восстановлена оргструктура: 3 отдела, 5 сотрудников",
                "org.structure"
            ),
            "Org structure recovered from the documents: 3 departments, 5 employees"
        );
        assert_eq!(
            en(
                "Раскрыта внутренняя инфраструктура: 1 сервер, домен corp.local",
                "net.internal_map"
            ),
            "Internal infrastructure disclosed: 1 server, domain corp.local"
        );
        assert_eq!(
            uk("Копии одного документа: 2 файла («a.docx»)", "doc.lineage"),
            "Копії одного документа: 2 файли («a.docx»)"
        );
        assert_eq!(
            en("Нет политики CSP", "recon.web.csp_missing"),
            "No CSP policy"
        );
        assert_eq!(
            en(
                "Поля: created, modified\nУверенность: 80%",
                "doc.anomaly.future_date"
            ),
            "Fields: created, modified\nConfidence: 80%"
        );
    }

    #[test]
    fn appended_sentences_translate_one_by_one() {
        // A templated description plus a caveat the core appends.
        assert_eq!(
            uk(
                "Shodan InternetDB сопоставил адресу 192.0.2.1 (a.example) 95 CVE по версиям ПО из баннеров. Это пассивные данные Shodan (без проверки), возможны ложные срабатывания из-за бэкпортов исправлений. Хост вне скоупа проекта: находка приведена как контекст окружения и не учитывается в оценке риска.",
                "internetdb-cve"
            ),
            "Shodan InternetDB зіставив адресі 192.0.2.1 (a.example) 95 CVE за версіями ПЗ із банерів. Це пасивні дані Shodan (без перевірки), можливі хибні спрацювання через бекпорти виправлень. Хост поза скоупом проєкту: знахідку наведено як контекст оточення, вона не враховується в оцінці ризику."
        );
        assert_eq!(
            en(
                "Технология обнаружена на хосте организации.\nЗатронутые хосты (1): a.example.\nЕсли патч-уровень ОС/дистрибутива не определён автоматически, сверьте версию 2.4.49 с бюллетенями производителя.",
                "sw.kev"
            ),
            "The technology was detected on a host of the organization.\nAffected hosts (1): a.example.\nIf the OS/distribution patch level was not detected automatically, check version 2.4.49 against the vendor bulletins."
        );
        // An unknown sentence stays, the known one is translated.
        assert_eq!(
            en(
                "Технология обнаружена на хосте организации. Что-то новое.",
                "sw.kev"
            ),
            "The technology was detected on a host of the organization. Что-то новое."
        );
    }

    /// The UI renders finding texts with a JavaScript port of this module (`ui/js/ftext.js`);
    /// both must agree on the shared vectors (`node qa/check-ftext.mjs --write` regenerates them).
    #[test]
    fn shared_vectors_match() {
        #[derive(Deserialize)]
        struct V {
            lang: String,
            rule: String,
            text: String,
            out: String,
        }
        let vs: Vec<V> =
            serde_json::from_str(include_str!("../tests/fixtures/ftext_vectors.json")).unwrap();
        assert!(vs.len() > 500);
        let bad: Vec<String> = vs
            .iter()
            .filter_map(|v| {
                let lang = if v.lang == "en" { Lang::En } else { Lang::Uk };
                let got = translate(&v.text, &v.rule, lang);
                (got != v.out).then(|| {
                    format!(
                        "{} {}: {}\n  want {}\n  got  {got}",
                        v.lang, v.rule, v.text, v.out
                    )
                })
            })
            .collect();
        assert!(
            bad.is_empty(),
            "{} mismatches:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    #[test]
    fn templates_are_well_formed() {
        let uk = locale_data(Lang::Uk);
        let en = locale_data(Lang::En);
        for (u, e) in uk.catalog.iter().zip(en.catalog.iter()) {
            let n = tokens(&u.pattern)
                .iter()
                .filter(|t| matches!(t, Tok::Any | Tok::Num))
                .count();
            for (lang_name, t) in [("uk", u.text.as_str()), ("en", e.text.as_str())] {
                let mut rest = t;
                while let Some(i) = rest.find('{') {
                    let j = rest[i..].find('}').map(|j| i + j).unwrap_or(rest.len());
                    let idx: usize = rest[i + 1..j]
                        .split([':', '!'])
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap_or_else(|_| panic!("{}: {t}", u.rules));
                    assert!(idx < n, "{}: {t} has no capture {idx}", u.rules);
                    rest = &rest[j + 1..];
                }
                if lang_name == "en" {
                    assert!(
                        !t.chars().any(|c| ('\u{400}'..='\u{4ff}').contains(&c)),
                        "Cyrillic in EN: {t}"
                    );
                }
            }
        }
    }
}
