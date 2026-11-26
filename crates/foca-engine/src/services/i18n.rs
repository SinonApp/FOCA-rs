//! Embedded UI and Help localization bundles (`locales/{en,ru,uk}/{ui,help}.json`, `ui/*.json`) served over
//! IPC (`i18n_bundle`) so the WebView never needs `fetch()` or a relaxed CSP (`connect-src`).

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

use foca_core::Lang;
use serde_json::{json, Value};

// ---------- core messages ----------
//
// Texts the core emits for the user (source details, command errors, notices, notifications)
// stay Russian in events and logs. Each one has a `core.<code>` key in `locales/<lang>/ui/core.json`
// whose Russian value is the exact emitted template (`{name}` marks a parameter). `classify`
// matches a text against those templates and returns `{ code, params }`; events carry it as
// `<field>_msg` next to the text so the UI can render it in its language.

/// Key prefixes of `core.json` that are rendered by key and never matched against texts.
const NOT_TEMPLATES: &[&str] = &["core.wordlist.", "core.device.", "core.plural."];

struct Template {
    code: String,
    /// Parameters never span "; " (the separator of joined notes).
    strict: regex::Regex,
    re: regex::Regex,
    names: Vec<String>,
    literal: usize,
}

fn templates() -> &'static [Template] {
    static T: OnceLock<Vec<Template>> = OnceLock::new();
    T.get_or_init(|| {
        let ph = regex::Regex::new(r"\{([a-z_]+)\}").expect("placeholder regex");
        let ru = ui_json(Lang::Ru).as_object().expect("ru ui object");
        let mut out: Vec<Template> = ru
            .iter()
            .filter(|(k, _)| {
                k.starts_with("core.") && !NOT_TEMPLATES.iter().any(|p| k.starts_with(p))
            })
            .filter_map(|(k, v)| {
                let tpl = v.as_str()?;
                let build = |param: &str| {
                    let mut re = String::from("(?s)^");
                    let mut last = 0;
                    for m in ph.find_iter(tpl) {
                        re.push_str(&regex::escape(&tpl[last..m.start()]));
                        re.push_str(param);
                        last = m.end();
                    }
                    re.push_str(&regex::escape(&tpl[last..]));
                    re.push('$');
                    regex::Regex::new(&re).ok()
                };
                let names = ph.captures_iter(tpl).map(|c| c[1].to_string()).collect();
                let fixed = ph.replace_all(tpl, "");
                // pure punctuation around parameters (`{a} ({b})`) would match any text
                if !fixed.chars().any(char::is_alphabetic) {
                    return None;
                }
                let literal = fixed.chars().count();
                Some(Template {
                    code: k["core.".len()..].to_string(),
                    strict: build("((?:[^;]|;[^ ])+?)")?,
                    re: build("(.+?)")?,
                    names,
                    literal,
                })
            })
            .collect();
        // the most specific template (longest fixed text) wins
        out.sort_by(|a, b| b.literal.cmp(&a.literal).then(a.code.cmp(&b.code)));
        out
    })
}

fn classify_one(text: &str, strict: bool) -> Option<Value> {
    let pick = |t: &'static Template| if strict { &t.strict } else { &t.re };
    let t = templates().iter().find(|t| pick(t).is_match(text))?;
    let caps = pick(t).captures(text)?;
    let mut params = serde_json::Map::new();
    for (i, name) in t.names.iter().enumerate() {
        let v = caps.get(i + 1).map_or("", |m| m.as_str());
        // a parameter may itself be a core message (`stopped: <captcha>; …`)
        let pv = match classify(v) {
            Some(mut m) if v.len() < text.len() => {
                m["text"] = json!(v);
                m
            }
            _ => json!(v),
        };
        params.insert(name.clone(), pv);
    }
    Some(json!({ "code": t.code, "params": params }))
}

/// Matches a Russian core text against the `core.*` templates: `{ code, params }`, or `None` for
/// free text. Notes joined with `"; "` come back as `{ code: "join", parts: [...] }` when every
/// part is known.
pub fn classify(text: &str) -> Option<Value> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(m) = classify_one(text, true) {
        return Some(m);
    }
    let segs: Vec<&str> = text.split("; ").collect();
    if segs.len() < 2 {
        return classify_one(text, false);
    }
    // the shortest run of segments that forms a known message (templates may contain "; ")
    let mut parts = Vec::new();
    let mut i = 0;
    while i < segs.len() {
        let mut hit = None;
        for j in i + 1..=segs.len() {
            let s = segs[i..j].join("; ");
            if let Some(mut m) = classify_one(&s, true) {
                m["text"] = json!(s);
                hit = Some((j, m));
                break;
            }
        }
        let Some((j, m)) = hit else {
            return classify_one(text, false);
        };
        parts.push(m);
        i = j;
    }
    Some(json!({ "code": "join", "parts": parts }))
}

/// Adds `<field>_msg` next to every listed string field of `obj` that holds a known core message.
pub fn annotate(obj: &mut Value, fields: &[&str]) {
    for f in fields {
        let m = obj.get(*f).and_then(Value::as_str).and_then(classify);
        if let Some(m) = m {
            obj[format!("{f}_msg")] = m;
        }
    }
}

fn fill(tpl: &str, params: &Value, lang: Lang) -> String {
    let ph = regex::Regex::new(r"\{([a-z_]+)\}").expect("placeholder regex");
    ph.replace_all(tpl, |c: &regex::Captures| match params.get(&c[1]) {
        Some(Value::String(s)) => s.clone(),
        Some(v @ Value::Object(_)) => render(lang, v, v["text"].as_str().unwrap_or("")),
        Some(Value::Number(n)) => n.to_string(),
        _ => c[0].to_string(),
    })
    .into_owned()
}

/// Renders a `{ code, params }` message in `lang`; `fallback` when the code is unknown.
pub fn render(lang: Lang, msg: &Value, fallback: &str) -> String {
    if msg["code"] == "join" {
        let parts: Vec<String> = msg["parts"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|p| render(lang, p, p["text"].as_str().unwrap_or("")))
                    .collect()
            })
            .unwrap_or_default();
        return parts.join("; ");
    }
    match msg["code"].as_str().and_then(|c| core_tpl(lang, c)) {
        Some(tpl) => fill(tpl, &msg["params"], lang),
        None => fallback.to_string(),
    }
}

fn core_tpl(lang: Lang, code: &str) -> Option<&'static str> {
    ui_json(lang).get(format!("core.{code}"))?.as_str()
}

/// `core.<code>` in `lang` with `{name}` parameters filled in (the code itself when missing).
pub fn core_text(lang: Lang, code: &str, params: &Value) -> String {
    match core_tpl(lang, code) {
        Some(tpl) => fill(tpl, params, lang),
        None => code.to_string(),
    }
}

/// Translates a Russian core text into `lang` (unchanged when it is free text).
pub fn localize(lang: Lang, text: &str) -> String {
    if lang == Lang::Ru {
        return text.to_string();
    }
    classify(text).map_or_else(|| text.to_string(), |m| render(lang, &m, text))
}

/// `"n word"` with the form from `core.plural.<key>` (`one|few|many`; English uses `one|other`).
pub fn plural(lang: Lang, n: u64, key: &str) -> String {
    let forms: Vec<&str> = core_tpl(lang, &format!("plural.{key}"))
        .unwrap_or("")
        .split('|')
        .collect();
    let pick = |i: usize| forms.get(i).or(forms.last()).copied().unwrap_or("");
    let w = if lang == Lang::En {
        pick(if n == 1 { 0 } else { 1 })
    } else {
        let (m10, m100) = (n % 10, n % 100);
        if m10 == 1 && m100 != 11 {
            pick(0)
        } else if (2..=4).contains(&m10) && !(12..=14).contains(&m100) {
            pick(1)
        } else {
            pick(2)
        }
    };
    format!("{n} {w}")
}

/// UI language of the last `i18n_bundle` in this process (0 = not resolved yet).
pub(crate) static UI_LANG: AtomicU8 = AtomicU8::new(0);

/// The UI language already resolved in this process, if any.
pub fn last_ui_lang() -> Option<Lang> {
    match UI_LANG.load(Ordering::Relaxed) {
        1 => Some(Lang::En),
        2 => Some(Lang::Ru),
        3 => Some(Lang::Uk),
        _ => None,
    }
}

pub(crate) fn lang_to_u8(l: Lang) -> u8 {
    match l {
        Lang::En => 1,
        Lang::Ru => 2,
        Lang::Uk => 3,
    }
}

/// Per-area UI dictionaries merged over `ui.json` (`locales/<lang>/ui/<area>.json`). Areas keep
/// screen strings in separate files so parallel work on different screens does not conflict.
macro_rules! ui_parts {
    ($lang:literal) => {
        [
            include_str!(concat!("../../../../locales/", $lang, "/ui.json")),
            include_str!(concat!("../../../../locales/", $lang, "/ui/workspace.json")),
            include_str!(concat!("../../../../locales/", $lang, "/ui/settings.json")),
            include_str!(concat!("../../../../locales/", $lang, "/ui/scan.json")),
            include_str!(concat!("../../../../locales/", $lang, "/ui/analysis.json")),
            include_str!(concat!("../../../../locales/", $lang, "/ui/tools.json")),
            include_str!(concat!("../../../../locales/", $lang, "/ui/core.json")),
        ]
    };
}

/// Merges the base dictionary and the area files; a key defined twice is a packaging error.
fn merge_ui(lang: &str, sources: &[&str]) -> Value {
    let mut out = serde_json::Map::new();
    for (i, src) in sources.iter().enumerate() {
        let v: Value = serde_json::from_str(src)
            .unwrap_or_else(|e| panic!("invalid {lang} ui locale part #{i}: {e}"));
        let obj = v
            .as_object()
            .unwrap_or_else(|| panic!("{lang} ui locale part #{i} is not an object"));
        for (k, val) in obj {
            assert!(
                out.insert(k.clone(), val.clone()).is_none(),
                "duplicate {lang} ui key {k}"
            );
        }
    }
    Value::Object(out)
}

pub(crate) fn ui_json(lang: Lang) -> &'static Value {
    static EN: OnceLock<Value> = OnceLock::new();
    static RU: OnceLock<Value> = OnceLock::new();
    static UK: OnceLock<Value> = OnceLock::new();
    match lang {
        Lang::En => EN.get_or_init(|| merge_ui("en", &ui_parts!("en"))),
        Lang::Ru => RU.get_or_init(|| merge_ui("ru", &ui_parts!("ru"))),
        Lang::Uk => UK.get_or_init(|| merge_ui("uk", &ui_parts!("uk"))),
    }
}

pub(crate) fn help_json(lang: Lang) -> &'static Value {
    static EN: OnceLock<Value> = OnceLock::new();
    static RU: OnceLock<Value> = OnceLock::new();
    static UK: OnceLock<Value> = OnceLock::new();
    match lang {
        Lang::En => EN.get_or_init(|| {
            serde_json::from_str(include_str!("../../../../locales/en/help.json"))
                .expect("valid locales/en/help.json")
        }),
        Lang::Ru => RU.get_or_init(|| {
            serde_json::from_str(include_str!("../../../../locales/ru/help.json"))
                .expect("valid locales/ru/help.json")
        }),
        Lang::Uk => UK.get_or_init(|| {
            serde_json::from_str(include_str!("../../../../locales/uk/help.json"))
                .expect("valid locales/uk/help.json")
        }),
    }
}

/// Finding texts catalog for the UI (`i18n_bundle().findings`): the report translations of finding
/// titles, descriptions, recommendations and evidence (`locales/<lang>/findings.json`: `catalog`,
/// `terms`, `roles`, `tech_cats`) plus the finding source labels (`sources` of `report.json`). The
/// core keeps writing these texts in Russian; the UI renders them by rule and template in its
/// language. `null` for Russian.
pub(crate) fn findings_json(lang: Lang) -> &'static Value {
    fn build(findings: &str, report: &str) -> Value {
        let f: Value = serde_json::from_str(findings).expect("valid findings locale");
        let r: Value = serde_json::from_str(report).expect("valid report locale");
        json!({
            "catalog": f["catalog"],
            "terms": f["terms"],
            "roles": f["roles"],
            "tech_cats": f["tech_cats"],
            "host_sources": f["host_sources"],
            "sources": r["sources"],
        })
    }
    static EN: OnceLock<Value> = OnceLock::new();
    static UK: OnceLock<Value> = OnceLock::new();
    static NONE: Value = Value::Null;
    match lang {
        Lang::En => EN.get_or_init(|| {
            build(
                include_str!("../../../../locales/en/findings.json"),
                include_str!("../../../../locales/en/report.json"),
            )
        }),
        Lang::Uk => UK.get_or_init(|| {
            build(
                include_str!("../../../../locales/uk/findings.json"),
                include_str!("../../../../locales/uk/report.json"),
            )
        }),
        Lang::Ru => &NONE,
    }
}

/// Normalizes a setting string (`"auto"` / `"en"` / `"ru"` / `"uk"` / `"ua"`) for serialization.
pub fn normalize_setting(raw: Option<&str>) -> String {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return "auto".into();
    };
    if s.eq_ignore_ascii_case("auto") {
        return "auto".into();
    }
    Lang::parse(s)
        .map(|l| l.code().to_string())
        .unwrap_or_else(|| "auto".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn timeline_texts_render_in_ui_language() {
        let en = |t: &str| localize(Lang::En, t);
        assert_eq!(en("Документы"), "Documents");
        assert_eq!(
            en("Самый ранний документ в выборке"),
            "Earliest document in the sample"
        );
        assert_eq!(
            en("Первый документ из Word 2016"),
            "First document from Word 2016"
        );
        assert_eq!(
            en("Последний документ: a.docx · поддержка до 2020-10-13"),
            "Last document: a.docx · supported until 2020-10-13"
        );
        assert_eq!(
            en("В путях появляется \\\\SRV-FILE01"),
            "\\\\SRV-FILE01 appears in paths"
        );
        assert_eq!(
            localize(Lang::Uk, "Фото с GPS-координатами: 50.4501, 30.5234"),
            "Фото з GPS-координатами: 50.4501, 30.5234"
        );
    }

    /// Every mail policy title and detail the core emits has a catalog entry (the mail policy
    /// screen and reports translate them with rule `mail-policy`).
    #[test]
    fn mail_policy_texts_are_in_the_findings_catalog() {
        use foca_net::mail::{analyze_mail, analyze_policies, DnssecStatus, PolicyInputs};
        let inp = PolicyInputs {
            mx: vec!["10 mx.example.test".into()],
            dnssec: DnssecStatus::Unsigned,
            ..Default::default()
        };
        let mut texts = Vec::new();
        for i in analyze_policies("example.test", &inp).issues {
            texts.extend([i.title, i.detail]);
        }
        for i in analyze_mail("example.test", &[], &[], &[], true).issues {
            texts.extend([i.title, i.detail]);
        }
        let catalog = findings_json(Lang::En)["catalog"].as_array().unwrap();
        let matches = |pat: &str, text: &str| {
            let re = regex::escape(pat).replace(r"\{\}", ".+");
            regex::Regex::new(&format!("^{re}$"))
                .unwrap()
                .is_match(text)
        };
        for t in texts.iter().filter(|t| !t.is_empty()) {
            assert!(
                catalog.iter().any(|c| {
                    c["rules"].as_str().is_some_and(|r| r.starts_with("mail-"))
                        && matches(c["pattern"].as_str().unwrap_or(""), t)
                }),
                "no catalog entry for {t:?}"
            );
        }
    }

    #[test]
    fn findings_catalog_is_served_for_en_and_uk() {
        assert!(findings_json(Lang::Ru).is_null());
        for l in [Lang::En, Lang::Uk] {
            let f = findings_json(l);
            assert!(f["catalog"].as_array().is_some_and(|c| c.len() > 100));
            for k in ["roles", "tech_cats", "host_sources", "sources"] {
                assert!(f[k].as_object().is_some_and(|m| !m.is_empty()), "{l:?} {k}");
            }
            assert!(f["terms"].is_array());
        }
        assert_eq!(
            findings_json(Lang::En)["sources"]["Скан портов"],
            "Port scan"
        );
        assert_eq!(
            findings_json(Lang::Uk)["host_sources"]["Пути в метаданных"],
            "Шляхи в метаданих"
        );
    }

    #[test]
    fn ui_locales_have_identical_non_empty_keys() {
        let en = ui_json(Lang::En).as_object().expect("en ui object");
        let ru = ui_json(Lang::Ru).as_object().expect("ru ui object");
        let uk = ui_json(Lang::Uk).as_object().expect("uk ui object");
        let ek: BTreeSet<_> = en.keys().collect();
        let rk: BTreeSet<_> = ru.keys().collect();
        let uk_k: BTreeSet<_> = uk.keys().collect();
        assert_eq!(ek, rk, "EN and RU ui.json keys diverged");
        assert_eq!(ek, uk_k, "EN and UK ui.json keys diverged");
        assert!(ek.len() >= 100);
        for (l, map) in [(Lang::En, en), (Lang::Ru, ru), (Lang::Uk, uk)] {
            for (k, v) in map {
                let s = v.as_str().unwrap_or_else(|| panic!("{l:?} {k} not string"));
                assert!(!s.trim().is_empty(), "{l:?} {k} is empty");
            }
        }
    }

    #[test]
    fn help_locales_have_identical_article_ids_and_structure() {
        let en = help_json(Lang::En);
        let ru = help_json(Lang::Ru);
        let uk = help_json(Lang::Uk);
        fn ids_of(v: &Value) -> Vec<&str> {
            v["articles"]
                .as_array()
                .expect("articles array")
                .iter()
                .map(|a| a["id"].as_str().expect("article id"))
                .collect()
        }
        let en_ids = ids_of(en);
        let ru_ids = ids_of(ru);
        let uk_ids = ids_of(uk);
        assert_eq!(en_ids, ru_ids, "EN and RU help.json article ids diverged");
        assert_eq!(en_ids, uk_ids, "EN and UK help.json article ids diverged");
        assert!(en_ids.len() >= 55);
        assert_eq!(
            en["screens"].as_array().unwrap().len(),
            ru["screens"].as_array().unwrap().len()
        );
        assert_eq!(
            en["screens"].as_array().unwrap().len(),
            uk["screens"].as_array().unwrap().len()
        );
        assert_eq!(
            en["glossary"].as_array().unwrap().len(),
            ru["glossary"].as_array().unwrap().len()
        );
        assert_eq!(
            en["glossary"].as_array().unwrap().len(),
            uk["glossary"].as_array().unwrap().len()
        );
    }

    /// Real texts the core emits; each must map to a `core.*` code with EN/UK translations.
    fn emitted_samples() -> Vec<String> {
        use foca_fuzz::StopReason;
        use foca_net::NetError;
        use foca_search::sources::{BLOCKED, CAPTCHA_WHY, VERIFY_WHY};
        let mut v: Vec<String> = vec![
            foca_search::source::limit_message("crtsh"),
            foca_search::source::limit_message("otx_dns"),
            foca_search::render::NO_RENDER.into(),
            format!("{BLOCKED}: {CAPTCHA_WHY}"),
            format!("{BLOCKED}: {VERIFY_WHY}"),
            format!("{BLOCKED}: поисковик заблокировал IP (automated queries, HTTP 403)"),
            "взял у других поисковиков групп: 2; остановлен: поисковик показал капчу (HTTP 202); \
             оставшиеся дорки переданы другим поисковикам"
                .into(),
            "все дорки уже выполнили другие поисковики".into(),
            "недоступно в фоновом режиме (нет WebView)".into(),
            "пропущен пользователем".into(),
            "нет ответа за 90 с".into(),
            "без скана портов (CDN/облако/общий хостинг): 203.0.113.5, CDN … ещё 3".into(),
            "Скан на паузе: питание, продолжится сам".into(),
            "Этап поиска уже закончился: проверка сохранена, следующий скан её использует".into(),
            "Скан был прерван системой. Продолжить не удалось: Скан уже идёт".into(),
            "Плановый скан завершён · Contoso".into(),
            crate::scan::steps::url_target_note("example.test"),
            crate::scan::search::queue_note_sample(),
            "Токен Telegram-бота не задан".into(),
            "Не указан chat_id".into(),
            "URL webhook не задан".into(),
            "неизвестный канал sms".into(),
        ];
        for e in [
            foca_net::notify::NotifyError::Rejected {
                status: 400,
                reason: "Bad Request".into(),
            },
            foca_net::notify::NotifyError::RateLimited { retry_after: 30 },
        ] {
            v.push(e.to_string());
        }
        for e in [
            NetError::Timeout,
            NetError::Cancelled,
            NetError::TooManyRedirects,
            NetError::NoKey("shodan".into()),
        ] {
            v.push(e.to_string());
        }
        for r in [
            StopReason::Completed,
            StopReason::Cancelled,
            StopReason::Budget,
            StopReason::MaxTime,
            StopReason::Blocked {
                detail: "HTTP 429".into(),
            },
        ] {
            v.push(r.message_ru());
        }
        v
    }

    #[test]
    fn core_messages_have_matching_placeholders_in_every_language() {
        let ph = regex::Regex::new(r"\{([a-z_]+)\}").unwrap();
        let names = |s: &str| -> BTreeSet<String> {
            ph.captures_iter(s).map(|c| c[1].to_string()).collect()
        };
        let ru = ui_json(Lang::Ru).as_object().unwrap();
        let core: Vec<_> = ru.iter().filter(|(k, _)| k.starts_with("core.")).collect();
        assert!(core.len() > 100);
        for (k, v) in core {
            let want = names(v.as_str().unwrap());
            for l in [Lang::En, Lang::Uk] {
                let t = ui_json(l)[k.as_str()]
                    .as_str()
                    .unwrap_or_else(|| panic!("{l:?} lacks {k}"));
                assert_eq!(names(t), want, "{l:?} {k} placeholders");
            }
        }
    }

    #[test]
    fn emitted_core_texts_have_codes_and_translations() {
        let cyr = |s: &str| s.chars().any(|c| matches!(c, '\u{0400}'..='\u{04FF}'));
        let ru_only = |s: &str| s.chars().any(|c| "ыэъёЫЭЪЁ".contains(c));
        for text in emitted_samples() {
            let m = classify(&text).unwrap_or_else(|| panic!("no core code for «{text}»"));
            assert_eq!(render(Lang::Ru, &m, ""), text, "RU render of {m}");
            let en = localize(Lang::En, &text);
            assert!(!cyr(&en), "EN still has Cyrillic: {en}");
            let uk = localize(Lang::Uk, &text);
            assert!(!ru_only(&uk), "UK has Russian-only letters: {uk}");
        }
    }

    #[test]
    fn classify_nests_messages_and_keeps_free_text() {
        let m = classify("капча / заблокировано: поисковик показал капчу").unwrap();
        assert_eq!(m["code"], "src.blocked");
        assert_eq!(m["params"]["why"]["code"], "src.captcha");
        assert_eq!(classify("connection refused (os error 111)"), None);
        assert_eq!(classify(""), None);
        let n = classify("нет ответа за 45 с").unwrap();
        assert_eq!(n["params"]["s"], "45");
        assert_eq!(plural(Lang::En, 1, "docs"), "1 document");
        assert_eq!(plural(Lang::Uk, 3, "docs"), "3 документи");
        assert_eq!(plural(Lang::Ru, 11, "findings"), "11 находок");
    }
}
