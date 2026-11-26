//! Cyrillic-to-Latin transliteration following national standards, and a "skeleton" for
//! fuzzy comparison of spellings.
//!
//! * Ukrainian: Cabinet of Ministers Resolution No. 55 of 27.01.2010 (passports). Iotated
//!   vowels become `ye/yi/y/yu/ya` at the start of a word and `ie/i/i/iu/ia` elsewhere; the
//!   `zg` cluster becomes `zgh`; the soft sign and the apostrophe are dropped.
//! * Russian: ICAO Doc 9303 (Russian passports since 2013, FMS order No. 320), e.g. `kh`,
//!   `ts`, `shch`, `iu`, `ia`, hard sign → `ie`.
//!
//! The language is detected from letters unique to each alphabet; if there are none, both
//! variants are produced.

/// Language of a Cyrillic spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    Latin,
    Ukrainian,
    Russian,
    /// Cyrillic without letters unique to either language: both standards apply.
    Cyrillic,
}

pub fn is_cyrillic(c: char) -> bool {
    matches!(c, '\u{0400}'..='\u{04FF}')
}

pub fn detect(s: &str) -> Script {
    let mut cyr = false;
    for c in s.chars().flat_map(char::to_lowercase) {
        match c {
            'і' | 'ї' | 'є' | 'ґ' => return Script::Ukrainian,
            'ы' | 'э' | 'ъ' | 'ё' => return Script::Russian,
            c if is_cyrillic(c) => cyr = true,
            _ => {}
        }
    }
    if cyr {
        Script::Cyrillic
    } else {
        Script::Latin
    }
}

fn uk_char(c: char, word_start: bool) -> &'static str {
    match c {
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' => "h",
        'ґ' => "g",
        'д' => "d",
        'е' => "e",
        'є' => {
            if word_start {
                "ye"
            } else {
                "ie"
            }
        }
        'ж' => "zh",
        'з' => "z",
        'и' => "y",
        'і' => "i",
        'ї' => {
            if word_start {
                "yi"
            } else {
                "i"
            }
        }
        'й' => {
            if word_start {
                "y"
            } else {
                "i"
            }
        }
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' => "u",
        'ф' => "f",
        'х' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "shch",
        'ь' | '\'' | '’' | 'ʼ' => "",
        'ю' => {
            if word_start {
                "yu"
            } else {
                "iu"
            }
        }
        'я' => {
            if word_start {
                "ya"
            } else {
                "ia"
            }
        }
        // Russian-only letters in Ukrainian text follow ICAO.
        'ё' => "e",
        'ы' => "y",
        'э' => "e",
        'ъ' => "ie",
        _ => "",
    }
}

fn ru_char(c: char) -> &'static str {
    match c {
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' => "g",
        'д' => "d",
        'е' | 'ё' | 'э' => "e",
        'ж' => "zh",
        'з' => "z",
        'и' | 'й' => "i",
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' => "u",
        'ф' => "f",
        'х' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "shch",
        'ъ' => "ie",
        'ы' => "y",
        'ь' | '\'' | '’' => "",
        'ю' => "iu",
        'я' => "ia",
        // Ukrainian-only letters in Russian text follow the Ukrainian standard.
        'і' => "i",
        'ї' => "i",
        'є' => "ie",
        'ґ' => "g",
        _ => "",
    }
}

/// Transliterates Ukrainian per the 2010 passport standard. Latin and other characters are
/// kept as is (lowercased).
pub fn uk(s: &str) -> String {
    let lower: Vec<char> = s.chars().flat_map(char::to_lowercase).collect();
    let mut out = String::with_capacity(lower.len() * 2);
    for (i, &c) in lower.iter().enumerate() {
        let start =
            i == 0 || !(lower[i - 1].is_alphabetic() || matches!(lower[i - 1], '\'' | '’' | 'ʼ'));
        if is_cyrillic(c) || matches!(c, '\'' | '’' | 'ʼ') {
            if c == 'г' && i > 0 && lower[i - 1] == 'з' {
                out.push_str("gh");
            } else {
                out.push_str(uk_char(c, start));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Transliterates Russian per ICAO Doc 9303.
pub fn ru(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars().flat_map(char::to_lowercase) {
        if is_cyrillic(c) || matches!(c, '\'' | '’') {
            out.push_str(ru_char(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Returns the lowercase Latin variants of a word: the word itself for Latin input, and for
/// Cyrillic the transliteration for the detected language (both if it is ambiguous).
pub fn variants(s: &str) -> Vec<String> {
    match detect(s) {
        Script::Latin => vec![s.to_lowercase()],
        Script::Ukrainian => vec![uk(s)],
        Script::Russian => vec![ru(s)],
        Script::Cyrillic => {
            let a = uk(s);
            let b = ru(s);
            if a == b {
                vec![a]
            } else {
                vec![a, b]
            }
        }
    }
}

/// Returns the primary variant, used to generate logins and addresses.
pub fn primary(s: &str) -> String {
    variants(s).into_iter().next().unwrap_or_default()
}

/// Returns the "skeleton" of a Latin spelling. It evens out differences between
/// transliteration systems (`kh/h`, `g/h`, `ia/ya/a`, `iu/yu/u`, `y/i/j`, `ts/tz/c`, double
/// letters) so that `Ihor`/`Igor`, `Yuliia`/`Iuliia`/`Yulia` and `Tkachenko`/`Tkatschenko`
/// match.
pub fn skeleton(latin: &str) -> String {
    let s: Vec<u8> = dedup(
        &latin
            .chars()
            .flat_map(char::to_lowercase)
            .filter(|c| c.is_ascii_alphabetic())
            .collect::<String>(),
    )
    .into_bytes();
    // Single greedy left-to-right pass; longer clusters first.
    const MULTI: &[(&[u8], &str)] = &[
        (b"shch", "s"),
        (b"tsch", "c"),
        (b"sch", "s"),
        (b"zh", "z"),
        (b"kh", "h"),
        (b"ts", "c"),
        (b"tz", "c"),
        (b"ch", "c"),
        (b"sh", "s"),
        (b"ck", "k"),
        (b"ya", "a"),
        (b"ia", "a"),
        (b"ja", "a"),
        (b"yu", "u"),
        (b"iu", "u"),
        (b"ju", "u"),
        (b"ye", "e"),
        (b"ie", "e"),
        (b"je", "e"),
        (b"yi", "i"),
    ];
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    'outer: while i < s.len() {
        for (pat, rep) in MULTI {
            if s[i..].starts_with(pat) {
                out.push_str(rep);
                i += pat.len();
                continue 'outer;
            }
        }
        match s[i] {
            b'y' | b'j' => out.push('i'),
            b'w' => out.push('v'),
            b'x' => out.push_str("ks"),
            b'g' => out.push('h'),
            b'q' => out.push('k'),
            c => out.push(c as char),
        }
        i += 1;
    }
    dedup(&out)
}

/// Collapses doubled letters.
fn dedup(s: &str) -> String {
    let mut res = String::with_capacity(s.len());
    let mut prev = '\0';
    for c in s.chars() {
        if c != prev {
            res.push(c);
        }
        prev = c;
    }
    res
}

/// Returns the possible Latin initials of a given name across transliteration systems
/// (Yuliia → `y`, `i`, `j`, `u`).
pub fn initials(name: &str) -> Vec<char> {
    let Some(c) = name
        .chars()
        .next()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
    else {
        return vec![];
    };
    let v: &[char] = match c {
        'ю' => &['y', 'i', 'j', 'u'],
        'я' => &['y', 'i', 'j', 'a'],
        'є' => &['y', 'i', 'j', 'e'],
        'е' => &['e', 'y'],
        'ї' | 'й' => &['y', 'i', 'j'],
        'х' => &['k', 'h'],
        'г' => &['h', 'g'],
        'ц' => &['t', 'c'],
        'ж' => &['z', 'j'],
        'ч' => &['c'],
        'ш' | 'щ' => &['s'],
        'и' => &['y', 'i'],
        'ё' | 'э' => &['e'],
        _ => {
            let l = primary(&c.to_string());
            return l.chars().next().into_iter().collect();
        }
    };
    v.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ukrainian_kmu_2010() {
        assert_eq!(uk("Ігор Петренко"), "ihor petrenko");
        assert_eq!(uk("Юлія Гриценко"), "yuliia hrytsenko");
        assert_eq!(uk("Олена Коваленко"), "olena kovalenko");
        assert_eq!(uk("Згорани"), "zghorany");
        assert_eq!(uk("Їжакевич"), "yizhakevych");
        assert_eq!(uk("Знам'янка"), "znamianka");
        assert_eq!(uk("Олексій"), "oleksii");
        assert_eq!(uk("Щербухи"), "shcherbukhy");
    }

    #[test]
    fn russian_icao() {
        assert_eq!(ru("Иван Петров"), "ivan petrov");
        assert_eq!(ru("Юлия Щукина"), "iuliia shchukina");
        assert_eq!(ru("Артём Хрущёв"), "artem khrushchev");
        assert_eq!(ru("Объедков"), "obieedkov");
        assert_eq!(detect("Сергей Быков"), Script::Russian);
        assert_eq!(detect("Петренко"), Script::Cyrillic);
        assert_eq!(variants("Петренко"), vec!["petrenko"]);
        assert_eq!(variants("Игорь").len(), 2);
    }

    #[test]
    fn skeleton_matches_systems() {
        assert_eq!(skeleton("Ihor"), skeleton("Igor"));
        assert_eq!(skeleton("Yuliia"), skeleton("Iuliia"));
        assert_eq!(skeleton("Yulia"), skeleton("Iuliia"));
        assert_eq!(skeleton("Tkachenko"), skeleton("tkatschenko"));
        assert_eq!(skeleton("Hrytsenko"), skeleton("Gritsenko"));
        assert_ne!(skeleton("Petrov"), skeleton("Petrova"));
        assert!(initials("Юлія").contains(&'y'));
        assert_eq!(initials("Андрій"), vec!['a']);
    }
}
