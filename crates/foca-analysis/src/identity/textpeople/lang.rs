//! Per-language data for people detection, loaded from `signatures/people/<code>.txt` at
//! build time (format: `signatures/people/README.md`).

pub use super::morph::{fold, Case, Gender};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use super::morph;

/// Writing system of a word or a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Script {
    Latin,
    Cyrillic,
    Arabic,
    Hebrew,
    Han,
    Hangul,
    Georgian,
    Armenian,
    Other,
}

impl Script {
    fn parse(s: &str) -> Script {
        match s.trim() {
            "latin" => Script::Latin,
            "cyrillic" => Script::Cyrillic,
            "arabic" => Script::Arabic,
            "hebrew" => Script::Hebrew,
            "han" | "kana" => Script::Han,
            "hangul" => Script::Hangul,
            "georgian" => Script::Georgian,
            "armenian" => Script::Armenian,
            _ => Script::Other,
        }
    }

    /// Script of one character.
    pub fn of(c: char) -> Script {
        match c as u32 {
            0x41..=0x5a | 0x61..=0x7a | 0xc0..=0x24f | 0x1e00..=0x1eff => Script::Latin,
            0x400..=0x52f | 0x1c80..=0x1c8f | 0x2de0..=0x2dff | 0xa640..=0xa69f => Script::Cyrillic,
            0x600..=0x6ff | 0x750..=0x77f | 0xfb50..=0xfdff | 0xfe70..=0xfeff => Script::Arabic,
            0x590..=0x5ff | 0xfb1d..=0xfb4f => Script::Hebrew,
            0x3040..=0x30ff | 0x3400..=0x4dbf | 0x4e00..=0x9fff | 0xf900..=0xfaff | 0x3005 => {
                Script::Han
            }
            0x1100..=0x11ff | 0x3130..=0x318f | 0xac00..=0xd7af => Script::Hangul,
            0x10a0..=0x10ff | 0x1c90..=0x1cbf => Script::Georgian,
            0x530..=0x58f => Script::Armenian,
            _ => Script::Other,
        }
    }

    /// Script of a word: the script of its first letter.
    pub fn of_word(w: &str) -> Script {
        w.chars()
            .find(|c| c.is_alphabetic())
            .map(Script::of)
            .unwrap_or(Script::Other)
    }
}

/// Built-in languages: code and data file.
const LANGS: &[(&str, &str)] = &[
    ("uk", include_str!("../../../signatures/people/uk.txt")),
    ("ru", include_str!("../../../signatures/people/ru.txt")),
    ("be", include_str!("../../../signatures/people/be.txt")),
    ("kk", include_str!("../../../signatures/people/kk.txt")),
    ("en", include_str!("../../../signatures/people/en.txt")),
    ("de", include_str!("../../../signatures/people/de.txt")),
    ("fr", include_str!("../../../signatures/people/fr.txt")),
    ("es", include_str!("../../../signatures/people/es.txt")),
    ("pt", include_str!("../../../signatures/people/pt.txt")),
    ("it", include_str!("../../../signatures/people/it.txt")),
    ("pl", include_str!("../../../signatures/people/pl.txt")),
    ("cs", include_str!("../../../signatures/people/cs.txt")),
    ("tr", include_str!("../../../signatures/people/tr.txt")),
    (
        "ar-latn",
        include_str!("../../../signatures/people/ar-latn.txt"),
    ),
    ("ar", include_str!("../../../signatures/people/ar.txt")),
    ("fa", include_str!("../../../signatures/people/fa.txt")),
    ("he", include_str!("../../../signatures/people/he.txt")),
    ("zh", include_str!("../../../signatures/people/zh.txt")),
    ("ja", include_str!("../../../signatures/people/ja.txt")),
    ("ko", include_str!("../../../signatures/people/ko.txt")),
    ("ka", include_str!("../../../signatures/people/ka.txt")),
    ("hy", include_str!("../../../signatures/people/hy.txt")),
];

/// A given name form: the nominative, gender and case of this form.
#[derive(Debug, Clone)]
pub struct Given {
    pub nom: String,
    pub gender: Gender,
    pub case: Case,
}

/// A position or title phrase.
#[derive(Debug, Clone)]
pub struct Title {
    pub pat: String,
    /// The word may continue after the pattern (`geschäftsführer*`).
    pub partial: bool,
    pub label: String,
}

struct LangInfo {
    code: &'static str,
    script: Script,
    common: Vec<String>,
}

/// All languages merged into lookup tables.
pub struct Registry {
    langs: Vec<LangInfo>,
    given: HashMap<String, Given>,
    ambiguous: HashSet<String>,
    family: HashMap<Script, HashSet<String>>,
    suffix: HashMap<Script, Vec<String>>,
    particles: HashSet<String>,
    honorifics: HashSet<String>,
    after: HashSet<String>,
    labels: Vec<String>,
    pub titles: Vec<Title>,
    stop: HashSet<String>,
    function: HashSet<String>,
}

fn sections(src: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for raw in src.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push((name.to_string(), Vec::new()));
        } else if let Some((_, v)) = out.last_mut() {
            v.push(line.to_string());
        }
    }
    out
}

fn words(lines: &[String]) -> impl Iterator<Item = &str> {
    lines.iter().flat_map(|l| l.split_whitespace())
}

fn build() -> Registry {
    let mut r = Registry {
        langs: Vec::new(),
        given: HashMap::new(),
        ambiguous: HashSet::new(),
        family: HashMap::new(),
        suffix: HashMap::new(),
        particles: HashSet::new(),
        honorifics: HashSet::new(),
        after: HashSet::new(),
        labels: Vec::new(),
        titles: Vec::new(),
        stop: HashSet::new(),
        function: HashSet::new(),
    };
    let mut slavic: Vec<(String, Gender, &'static str)> = Vec::new();
    for (code, src) in LANGS {
        let secs = sections(src);
        let script = secs
            .iter()
            .find(|(n, _)| n == "script")
            .and_then(|(_, v)| v.first())
            .map(|s| Script::parse(s))
            .unwrap_or(Script::Other);
        let mut common = Vec::new();
        for (name, lines) in &secs {
            match name.as_str() {
                "common" => common.extend(words(lines).map(fold)),
                "given_m" | "given_f" | "given" => {
                    let g = match name.as_str() {
                        "given_m" => Gender::Male,
                        "given_f" => Gender::Female,
                        _ => Gender::Unknown,
                    };
                    for w in words(lines) {
                        r.given.entry(fold(w)).or_insert_with(|| Given {
                            nom: w.replace(['’', 'ʼ'], "'"),
                            gender: g,
                            case: Case::Nom,
                        });
                        if matches!(*code, "uk" | "ru" | "be") {
                            slavic.push((w.to_string(), g, code));
                        }
                    }
                }
                "ambiguous" => r.ambiguous.extend(words(lines).map(fold)),
                "family" => r
                    .family
                    .entry(script)
                    .or_default()
                    .extend(words(lines).map(fold)),
                "surname_suffix" => r
                    .suffix
                    .entry(script)
                    .or_default()
                    .extend(words(lines).map(fold)),
                "particles" => r.particles.extend(words(lines).map(fold)),
                "honorifics" => r
                    .honorifics
                    .extend(words(lines).map(|w| fold(w).trim_end_matches('.').to_string())),
                "after" => r
                    .after
                    .extend(words(lines).map(|w| fold(w).trim_end_matches('.').to_string())),
                "labels" => r.labels.extend(words(lines).map(fold)),
                "titles" => {
                    for l in lines {
                        let (label, vars) = match l.split_once('=') {
                            Some((a, b)) => (a.trim(), b),
                            None => (l.trim(), l.as_str()),
                        };
                        for v in vars.split(';').map(str::trim).filter(|v| !v.is_empty()) {
                            let partial = v.ends_with('*');
                            r.titles.push(Title {
                                pat: fold(v.trim_end_matches('*')),
                                partial,
                                label: label.to_string(),
                            });
                        }
                    }
                }
                "stop" => r.stop.extend(words(lines).map(fold)),
                _ => {}
            }
        }
        r.function.extend(common.iter().cloned());
        r.langs.push(LangInfo {
            code,
            script,
            common,
        });
    }
    r.labels.sort_by_key(|l| std::cmp::Reverse(l.len()));
    r.labels.dedup();
    r.titles
        .sort_by_key(|t| std::cmp::Reverse(t.pat.chars().count()));
    // Latin spellings of Slavic given names (`Olena`, `Oleksandr`, `Sergey`).
    for (w, g, _) in &slavic {
        for lat in [crate::translit::uk(w), crate::translit::ru(w)] {
            let nom = super::morph::title_case(&lat);
            r.given.entry(lat).or_insert_with(|| Given {
                nom,
                gender: *g,
                case: Case::Nom,
            });
        }
    }
    // Slavic case forms after all nominatives, so a nominative is never shadowed.
    for (w, g, code) in slavic {
        for (form, case) in morph::given_forms(&w, g, code) {
            r.given.entry(form).or_insert_with(|| Given {
                nom: w.replace(['’', 'ʼ'], "'"),
                gender: g,
                case,
            });
        }
    }
    r
}

pub fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(build)
}

impl Registry {
    /// Given name in any known form.
    pub fn given(&self, w: &str) -> Option<Given> {
        let f = fold(w);
        if let Some(g) = self.given.get(&f) {
            return Some(g.clone());
        }
        // Hyphenated given names: `Anna-Lena`, `Jean-Pierre`, `Марія-Олена`.
        let parts: Vec<&str> = f.split('-').collect();
        if parts.len() == 2
            && parts
                .iter()
                .all(|p| self.given.get(*p).is_some_and(|g| g.case == Case::Nom))
        {
            let first = self.given.get(parts[0])?;
            return Some(Given {
                nom: w.to_string(),
                gender: first.gender,
                case: Case::Nom,
            });
        }
        None
    }

    pub fn ambiguous(&self, nom: &str) -> bool {
        self.ambiguous.contains(&fold(nom))
    }

    pub fn stop(&self, w: &str) -> bool {
        let f = fold(w);
        self.stop.contains(&f)
            || (f.contains(['-', '\'']) && f.split(['-', '\'']).any(|p| self.stop.contains(p)))
    }

    pub fn particle(&self, w: &str) -> bool {
        self.particles.contains(&fold(w))
    }

    pub fn honorific(&self, w: &str) -> bool {
        self.honorifics.contains(fold(w).trim_end_matches('.'))
    }

    pub fn after(&self, w: &str) -> bool {
        self.after.contains(fold(w).trim_end_matches('.'))
    }

    /// Family names of a script (CJK).
    pub fn family(&self, s: Script, w: &str) -> bool {
        self.family.get(&s).is_some_and(|f| f.contains(w))
    }

    /// Words after which a name follows (`Name:`, `ПІБ`, `姓名`), longest first.
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// `true` when the word ends like a surname of its script.
    pub fn surname_suffix(&self, w: &str) -> bool {
        let f = fold(w);
        let n = f.chars().count();
        self.suffix.get(&Script::of_word(w)).is_some_and(|v| {
            v.iter()
                .any(|s| n > s.chars().count() + 1 && f.ends_with(s.as_str()))
        })
    }

    /// `true` for a frequent function word of any language.
    pub fn function_word(&self, w: &str) -> bool {
        self.function.contains(&fold(w))
    }

    /// Guesses the language of a text from function-word frequencies (first ~4000 words).
    pub fn guess(&self, text: &str) -> &'static str {
        let mut counts: HashMap<&'static str, u32> = HashMap::new();
        let mut scripts: HashMap<Script, u32> = HashMap::new();
        for w in text
            .split(|c: char| !c.is_alphabetic())
            .filter(|w| !w.is_empty())
            .take(4000)
        {
            let s = Script::of_word(w);
            *scripts.entry(s).or_default() += 1;
            let f = fold(w);
            for l in &self.langs {
                if l.script == s && l.common.contains(&f) {
                    *counts.entry(l.code).or_default() += 1;
                }
            }
        }
        // CJK has no spaces: one "word" is a whole run, so look at the characters.
        let kana = text
            .chars()
            .take(20000)
            .any(|c| ('\u{3040}'..='\u{30ff}').contains(&c));
        let top_script = scripts
            .iter()
            .max_by_key(|(s, n)| (**n, std::cmp::Reverse(**s)))
            .map(|(s, _)| *s);
        match top_script {
            Some(Script::Han) => return if kana { "ja" } else { "zh" },
            Some(Script::Hangul) => return "ko",
            Some(Script::Georgian) => return "ka",
            Some(Script::Armenian) => return "hy",
            Some(Script::Hebrew) => return "he",
            _ => {}
        }
        counts
            .into_iter()
            .max_by_key(|(c, n)| (*n, std::cmp::Reverse(*c)))
            .map(|(c, _)| c)
            .unwrap_or("und")
    }

    /// The language code used for a line of `script` in a document guessed as `doc`.
    pub fn lang_for(&self, script: Script, doc: &'static str) -> &'static str {
        if self
            .langs
            .iter()
            .any(|l| l.code == doc && l.script == script)
        {
            return doc;
        }
        match script {
            Script::Latin => "en",
            Script::Cyrillic => "ru",
            Script::Arabic => "ar",
            Script::Hebrew => "he",
            Script::Han => "zh",
            Script::Hangul => "ko",
            Script::Georgian => "ka",
            Script::Armenian => "hy",
            Script::Other => "und",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_files_load() {
        let r = registry();
        assert_eq!(r.langs.len(), LANGS.len());
        assert_eq!(r.given("Olena").map(|g| g.nom), Some("Olena".to_string()));
        assert_eq!(r.given("Івану").map(|g| g.nom), Some("Іван".to_string()));
        assert!(r.given("Anna-Lena").is_some());
        assert!(r.given("Jürgen").is_some());
        assert!(r.family(Script::Han, "王"));
        assert!(r.family(Script::Hangul, "김"));
        assert!(r.honorific("Dr."));
        assert!(r.particle("von"));
        assert!(r.stop("Університету"));
        assert!(r.titles.iter().any(|t| t.label == "geschäftsführer"));
        assert_eq!(
            r.guess("Der Vertrag wird von der Firma und dem Kunden unterschrieben, das ist nicht"),
            "de"
        );
        assert_eq!(
            r.guess("Це документ для студентів та викладачів, які навчаються"),
            "uk"
        );
        assert_eq!(r.guess("联系人：王伟先生"), "zh");
    }
}
