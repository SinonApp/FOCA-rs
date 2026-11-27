//! National identifiers, IBANs of every country and national phone formats, with check digits
//! wherever an official algorithm exists.
//!
//! Ukrainian RNOKPP / EDRPOU / IBAN `UA`, payment cards and Ukrainian passports live in
//! [`crate::pii`]; this module adds the other countries:
//!
//! | id | country | check |
//! |---|---|---|
//! | `ru_inn` | RU INN (10 or 12 digits) | weighted mod 11 |
//! | `ru_snils` | RU SNILS | mod 101 |
//! | `ru_ogrn` | RU OGRN / OGRNIP | mod 11 / mod 13 |
//! | `pl_pesel` | PL PESEL | weighted mod 10 + birth date |
//! | `pl_nip` | PL NIP | weighted mod 11 |
//! | `de_steuer_id` | DE Steuer-ID | ISO 7064 MOD 11,10 |
//! | `us_ssn` | US SSN | area/group/serial ranges, context only |
//! | `uk_nino` | UK National Insurance number | prefix rules |
//! | `es_dni` | ES DNI / NIE | mod 23 letter |
//! | `it_cf` | IT codice fiscale | odd/even table check letter |
//! | `fr_nir` | FR NIR (social security) | 97 - n mod 97, context only |
//! | `iban` | IBAN of any country except UA | ISO 13616 mod 97 + country length |
//! | `passport` | passport numbers next to a passport word in any language | context only |
//!
//! Numbers that are only digits demand a context word (`ИНН`, `PESEL`, `Steuer-ID`, ...);
//! letter-bearing formats with a check character (DNI, codice fiscale, NINO) stand alone.

use std::sync::OnceLock;

use regex::Regex;

/// One identifier found in text.
#[derive(Clone, PartialEq, Eq)]
pub struct IdHit {
    /// Stable id (`pl_pesel`, `iban`, ...).
    pub kind: &'static str,
    /// Display label (`PL PESEL`).
    pub label: &'static str,
    pub start: usize,
    pub end: usize,
    /// Normalised value (no separators).
    pub value: String,
}

impl std::fmt::Debug for IdHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdHit")
            .field("kind", &self.kind)
            .field("start", &self.start)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("builtin id regex")
}

macro_rules! lazy_re {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| re($pat))
        }
    };
}

lazy_re!(re_digits, r"\d[\d \-\u00a0]{6,22}\d");
lazy_re!(re_ssn, r"\b(\d{3})-(\d{2})-(\d{4})\b");
lazy_re!(
    re_nino,
    r"\b([A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]) ?(\d{2}) ?(\d{2}) ?(\d{2}) ?([A-D])\b"
);
lazy_re!(re_dni, r"\b([XYZ]?)(\d{7,8})[\- ]?([A-Z])\b");
lazy_re!(
    re_cf,
    r"\b[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]\b"
);
lazy_re!(
    re_iban,
    r"\b([A-Z]{2})(\d{2})((?:[ \u00a0]?[A-Z0-9]){10,30})"
);
lazy_re!(
    re_nir,
    r"\b([12])[ ]?(\d{2})[ ]?(\d{2})[ ]?(\d{2}|2A|2B)[ ]?(\d{3})[ ]?(\d{3})[ ]?(\d{2})\b"
);
lazy_re!(re_passport_no, r"\b([A-Z]{0,2}[0-9][A-Z0-9]{5,8})\b");

/// Lower-cased text around a match (60 characters before, 25 after) on the same line.
fn around(text: &str, s: usize, e: usize) -> String {
    let ls = text[..s].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let le = text[e..].find('\n').map(|i| e + i).unwrap_or(text.len());
    let b: String = {
        let part = &text[ls..s];
        let n = part.chars().count();
        part.chars().skip(n.saturating_sub(60)).collect()
    };
    let a: String = text[e..le].chars().take(25).collect();
    format!("{b} {a}").to_lowercase()
}

/// A context word around the match, starting at a word boundary (`tel` in `Tel.:`, not in
/// `Intel`).
fn near(text: &str, s: usize, e: usize, words: &[&str]) -> bool {
    let a = around(text, s, e);
    words.iter().any(|w| {
        a.match_indices(w).any(|(i, _)| {
            a[..i]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_alphabetic())
        })
    })
}

fn glued(text: &str, s: usize, e: usize) -> bool {
    let p = text[..s].chars().next_back();
    let n = text[e..].chars().next();
    p.is_some_and(|c| c.is_alphanumeric()) || n.is_some_and(|c| c.is_alphanumeric())
}

fn dv(s: &str) -> Vec<u32> {
    s.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| (b - b'0') as u32)
        .collect()
}

fn weighted(d: &[u32], w: &[u32]) -> u32 {
    d.iter().zip(w).map(|(a, b)| a * b).sum()
}

/// RU INN, 10 (legal entity) or 12 digits (individual).
pub fn ru_inn_valid(s: &str) -> bool {
    let d = dv(s);
    let c = |w: &[u32], n: usize| (weighted(&d[..n], w) % 11) % 10;
    match d.len() {
        10 => c(&[2, 4, 10, 3, 5, 9, 4, 6, 8], 9) == d[9],
        12 => {
            c(&[7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 10) == d[10]
                && c(&[3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 11) == d[11]
        }
        _ => false,
    }
}

/// RU SNILS (11 digits, the last two are the check number).
pub fn ru_snils_valid(s: &str) -> bool {
    let d = dv(s);
    if d.len() != 11 {
        return false;
    }
    let sum: u32 = d[..9]
        .iter()
        .enumerate()
        .map(|(i, x)| x * (9 - i as u32))
        .sum();
    let check = match sum {
        0..=99 => sum,
        100 | 101 => 0,
        _ => match sum % 101 {
            100 => 0,
            r => r,
        },
    };
    check == d[9] * 10 + d[10]
}

/// RU OGRN (13 digits) or OGRNIP (15 digits).
pub fn ru_ogrn_valid(s: &str) -> bool {
    let d: String = s.chars().filter(char::is_ascii_digit).collect();
    let (body, m) = match d.len() {
        13 => (&d[..12], 11u64),
        15 => (&d[..14], 13u64),
        _ => return false,
    };
    let Ok(n) = body.parse::<u64>() else {
        return false;
    };
    let last = d.as_bytes()[d.len() - 1] - b'0';
    ((n % m) % 10) as u8 == last
}

/// PL PESEL: check digit and an existing birth date.
pub fn pl_pesel_valid(s: &str) -> bool {
    let d = dv(s);
    if d.len() != 11 {
        return false;
    }
    let sum = weighted(&d[..10], &[1, 3, 7, 9, 1, 3, 7, 9, 1, 3]);
    if (10 - sum % 10) % 10 != d[10] {
        return false;
    }
    let month = (d[2] * 10 + d[3]) % 20;
    let day = d[4] * 10 + d[5];
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

/// PL NIP (tax number).
pub fn pl_nip_valid(s: &str) -> bool {
    let d = dv(s);
    d.len() == 10 && {
        let c = weighted(&d[..9], &[6, 5, 7, 2, 3, 4, 5, 6, 7]) % 11;
        c != 10 && c == d[9]
    }
}

/// DE Steuer-ID (11 digits, ISO 7064 MOD 11,10; one digit repeated twice or thrice).
pub fn de_steuer_id_valid(s: &str) -> bool {
    let d = dv(s);
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    let mut counts = [0u8; 10];
    for x in &d[..10] {
        counts[*x as usize] += 1;
    }
    let repeated = counts.iter().filter(|c| **c >= 2).count();
    if repeated != 1 || counts.iter().any(|c| *c > 3) {
        return false;
    }
    let mut product = 10;
    for x in &d[..10] {
        let mut sum = (x + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let check = match 11 - product {
        10 => 0,
        c => c,
    };
    check == d[10]
}

/// ES DNI (8 digits + letter) or NIE (X/Y/Z + 7 digits + letter).
pub fn es_dni_valid(prefix: &str, digits: &str, letter: char) -> bool {
    const L: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let lead = match prefix {
        "" if digits.len() == 8 => "",
        "X" if digits.len() == 7 => "0",
        "Y" if digits.len() == 7 => "1",
        "Z" if digits.len() == 7 => "2",
        _ => return false,
    };
    let Ok(n) = format!("{lead}{digits}").parse::<u64>() else {
        return false;
    };
    L[(n % 23) as usize] as char == letter
}

/// IT codice fiscale check letter.
pub fn it_cf_valid(s: &str) -> bool {
    const ODD: [u32; 26] = [
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24,
        23,
    ];
    let b = s.as_bytes();
    if b.len() != 16 {
        return false;
    }
    let val = |c: u8| -> Option<usize> {
        match c {
            b'0'..=b'9' => Some((c - b'0') as usize),
            b'A'..=b'Z' => Some((c - b'A') as usize),
            _ => None,
        }
    };
    let mut sum = 0u32;
    for (i, c) in b[..15].iter().enumerate() {
        let Some(v) = val(*c) else { return false };
        sum += if i % 2 == 0 { ODD[v] } else { v as u32 };
    }
    (b'A' + (sum % 26) as u8) == b[15]
}

/// FR NIR key: 97 - (number mod 97); Corsica `2A`/`2B` count as 19/18.
pub fn fr_nir_valid(body13: &str, key: &str) -> bool {
    let n = body13.replace("2A", "19").replace("2B", "18");
    let (Ok(n), Ok(k)) = (n.parse::<u64>(), key.parse::<u64>()) else {
        return false;
    };
    97 - n % 97 == k
}

/// IBAN lengths per country (ISO 13616 registry).
const IBAN_LEN: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BR", 29),
    ("BY", 28),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IQ", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LC", 32),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NL", 18),
    ("NO", 15),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("SA", 24),
    ("SC", 31),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("ST", 25),
    ("SV", 28),
    ("TL", 23),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VA", 22),
    ("VG", 24),
    ("XK", 20),
];

/// ISO 13616 mod 97 over a cleaned IBAN.
pub fn iban_valid(s: &str) -> bool {
    let Some(&(_, len)) = IBAN_LEN.iter().find(|(c, _)| s.starts_with(c)) else {
        return false;
    };
    if s.len() != len
        || !s
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return false;
    }
    let mut r: u32 = 0;
    for b in s[4..].bytes().chain(s[..4].bytes()) {
        let v = if b.is_ascii_digit() {
            (b - b'0') as u32
        } else {
            (b - b'A') as u32 + 10
        };
        r = if v >= 10 {
            (r * 100 + v) % 97
        } else {
            (r * 10 + v) % 97
        };
    }
    r == 1
}

const INN_WORDS: &[&str] = &["инн", "inn", "taxpayer"];
const SNILS_WORDS: &[&str] = &["снилс", "страхов", "snils"];
const OGRN_WORDS: &[&str] = &["огрн", "ogrn"];
const PESEL_WORDS: &[&str] = &["pesel"];
const NIP_WORDS: &[&str] = &["nip"];
const STEUER_WORDS: &[&str] = &[
    "steuer-id",
    "steuerid",
    "steuer-identifikationsnummer",
    "steueridentifikationsnummer",
    "identifikationsnummer",
    "idnr",
    "tin",
];
const SSN_WORDS: &[&str] = &["ssn", "social security"];
const NINO_WORDS: &[&str] = &["national insurance", "nino", "ni number", "ni no"];
const NIR_WORDS: &[&str] = &[
    "sécurité sociale",
    "securite sociale",
    "nir",
    "n° ss",
    "insee",
    "numéro de sécu",
];
/// Passport words in many languages.
pub const PASSPORT_WORDS: &[&str] = &[
    "passport",
    "паспорт",
    "reisepass",
    "pass-nr",
    "passnummer",
    "passeport",
    "pasaporte",
    "passaporto",
    "passaporte",
    "paszport",
    "pasaport",
    "cestovní pas",
    "护照",
    "護照",
    "旅券",
    "여권",
    "جواز",
    "דרכון",
    "пашпарт",
];

/// Finds national identifiers (see the module table) in `text`.
pub fn scan_ids(text: &str) -> Vec<IdHit> {
    let mut out: Vec<IdHit> = Vec::new();
    let push = |out: &mut Vec<IdHit>, kind, label, s: usize, e: usize, value: String| {
        if !out.iter().any(|h| h.start < e && s < h.end) {
            out.push(IdHit {
                kind,
                label,
                start: s,
                end: e,
                value,
            });
        }
    };
    if !text.bytes().any(|b| b.is_ascii_digit()) {
        return out;
    }
    for m in re_iban().captures_iter(text) {
        let (Some(all), Some(cc)) = (m.get(0), m.get(1)) else {
            continue;
        };
        if cc.as_str() == "UA"
            || text[..all.start()]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric())
        {
            continue;
        }
        let Some(&(_, len)) = IBAN_LEN.iter().find(|(c, _)| *c == cc.as_str()) else {
            continue;
        };
        // Take exactly the country length, so a following word is not swallowed.
        let mut clean = String::new();
        let mut end = all.start();
        for (i, c) in all.as_str().char_indices() {
            if clean.len() == len {
                break;
            }
            if c.is_ascii_alphanumeric() {
                clean.push(c);
                end = all.start() + i + c.len_utf8();
            }
        }
        if text[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
            && !text[end..].starts_with(' ')
        {
            continue;
        }
        if iban_valid(&clean) {
            push(&mut out, "iban", "IBAN", all.start(), end, clean);
        }
    }
    for m in re_cf().find_iter(text) {
        if it_cf_valid(m.as_str()) {
            push(
                &mut out,
                "it_cf",
                "IT codice fiscale",
                m.start(),
                m.end(),
                m.as_str().into(),
            );
        }
    }
    for c in re_dni().captures_iter(text) {
        let (Some(all), Some(p), Some(d), Some(l)) = (c.get(0), c.get(1), c.get(2), c.get(3))
        else {
            continue;
        };
        let letter = l.as_str().chars().next().unwrap_or(' ');
        if es_dni_valid(p.as_str(), d.as_str(), letter) {
            push(
                &mut out,
                "es_dni",
                "ES DNI/NIE",
                all.start(),
                all.end(),
                format!("{}{}{}", p.as_str(), d.as_str(), letter),
            );
        }
    }
    for c in re_nino().captures_iter(text) {
        let Some(all) = c.get(0) else { continue };
        let pre = c.get(1).map(|m| m.as_str()).unwrap_or("");
        if ["BG", "GB", "NK", "KN", "TN", "NT", "ZZ"].contains(&pre) {
            continue;
        }
        let spaced = all.as_str().matches(' ').count() == 4;
        if spaced || near(text, all.start(), all.end(), NINO_WORDS) {
            let v: String = all.as_str().chars().filter(|c| *c != ' ').collect();
            push(&mut out, "uk_nino", "UK NINO", all.start(), all.end(), v);
        }
    }
    for c in re_ssn().captures_iter(text) {
        let (Some(all), Some(a), Some(g), Some(n)) = (c.get(0), c.get(1), c.get(2), c.get(3))
        else {
            continue;
        };
        let area = a.as_str();
        if area == "000"
            || area == "666"
            || area.starts_with('9')
            || g.as_str() == "00"
            || n.as_str() == "0000"
        {
            continue;
        }
        if near(text, all.start(), all.end(), SSN_WORDS) {
            push(
                &mut out,
                "us_ssn",
                "US SSN",
                all.start(),
                all.end(),
                format!("{}{}{}", area, g.as_str(), n.as_str()),
            );
        }
    }
    for c in re_nir().captures_iter(text) {
        let Some(all) = c.get(0) else { continue };
        let parts: Vec<&str> = (1..=6)
            .filter_map(|i| c.get(i))
            .map(|m| m.as_str())
            .collect();
        let key = c.get(7).map(|m| m.as_str()).unwrap_or("");
        let body = parts.concat();
        if body.len() == 13
            && fr_nir_valid(&body, key)
            && near(text, all.start(), all.end(), NIR_WORDS)
        {
            push(
                &mut out,
                "fr_nir",
                "FR NIR",
                all.start(),
                all.end(),
                format!("{body}{key}"),
            );
        }
    }
    for m in re_digits().find_iter(text) {
        let raw = m.as_str().trim_end_matches([' ', '-', '\u{a0}']);
        let (s, e) = (m.start(), m.start() + raw.len());
        if glued(text, s, e) {
            continue;
        }
        let d: String = raw.chars().filter(char::is_ascii_digit).collect();
        // Separators are allowed only in the usual groupings (SNILS `123-456-789 01`, NIP).
        let seps = raw.chars().any(|c| !c.is_ascii_digit());
        let checks: [DigitCheck; 7] = [
            ("ru_inn", "RU INN", INN_WORDS, ru_inn_valid, false),
            ("ru_snils", "RU SNILS", SNILS_WORDS, ru_snils_valid, true),
            ("ru_ogrn", "RU OGRN", OGRN_WORDS, ru_ogrn_valid, false),
            ("pl_pesel", "PL PESEL", PESEL_WORDS, pl_pesel_valid, false),
            ("pl_nip", "PL NIP", NIP_WORDS, pl_nip_valid, true),
            (
                "de_steuer_id",
                "DE Steuer-ID",
                STEUER_WORDS,
                de_steuer_id_valid,
                true,
            ),
            (
                "ru_inn",
                "RU INN",
                &["инн физ", "инн:"],
                ru_inn_valid,
                false,
            ),
        ];
        for (kind, label, words, valid, sep_ok) in checks {
            if (seps && !sep_ok) || !valid(&d) {
                continue;
            }
            if near(text, s, e, words) {
                push(&mut out, kind, label, s, e, d.clone());
                break;
            }
        }
    }
    for m in re_passport_no().find_iter(text) {
        let (s, e) = (m.start(), m.end());
        if out.iter().any(|h| h.start < e && s < h.end) {
            continue;
        }
        let ls = text[..s].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let before: String = {
            let p = &text[ls..s];
            let n = p.chars().count();
            p.chars()
                .skip(n.saturating_sub(30))
                .collect::<String>()
                .to_lowercase()
        };
        if PASSPORT_WORDS.iter().any(|w| before.contains(w))
            && m.as_str().chars().filter(char::is_ascii_digit).count() >= 5
        {
            push(&mut out, "passport", "passport", s, e, m.as_str().into());
        }
    }
    out.sort_by_key(|h| h.start);
    out
}

/// A phone number in a national format.
#[derive(Clone, PartialEq, Eq)]
pub struct PhoneMatch {
    pub start: usize,
    pub end: usize,
    /// E.164 digits with `+` when the country is known, otherwise the national digits.
    pub value: String,
    /// ISO country code (`US`, `DE`, ...), or `` when only the number shape is known.
    pub country: &'static str,
}

impl std::fmt::Debug for PhoneMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneMatch")
            .field("country", &self.country)
            .field("start", &self.start)
            .finish_non_exhaustive()
    }
}

/// Phone words in many languages.
pub const PHONE_WORDS: &[&str] = &[
    "tel",
    "tél",
    "тел",
    "phone",
    "моб",
    "mob",
    "fax",
    "факс",
    "cell",
    "handy",
    "telefon",
    "téléphone",
    "teléfono",
    "telefono",
    "telefone",
    "tlf",
    "móvil",
    "movil",
    "cellulare",
    "celular",
    "portable",
    "gsm",
    "viber",
    "whatsapp",
    "telegram",
    "電話",
    "电话",
    "전화",
    "هاتف",
    "تلفن",
    "טלפון",
    "тэл",
];

/// Ukrainian operator or area code of a national number `0XX...`.
fn ua_code(d: &str) -> bool {
    const MOBILE: &[&str] = &[
        "039", "050", "063", "066", "067", "068", "073", "089", "091", "092", "093", "094", "095",
        "096", "097", "098", "099",
    ];
    d.starts_with('0') && (MOBILE.contains(&&d[..3]) || matches!(d.as_bytes()[1], b'3'..=b'6'))
}

/// `044 201 08 47`, `044-201-08-47`: the usual 3-3-2-2 grouping.
fn ua_shape(raw: &str) -> bool {
    let g: Vec<usize> = raw
        .split(|c: char| !c.is_ascii_digit())
        .filter(|g| !g.is_empty())
        .map(str::len)
        .collect();
    g == [3, 3, 2, 2] || g == [3, 7] || g == [4, 2, 2, 2]
}

lazy_re!(
    re_national,
    r"(?:^|[^\d+])((?:\(\d{2,5}\)|\d{1,5})(?:[ .\-\u00a0/]?\(?\d{1,5}\)?){1,5})"
);

/// Digit-only identifier check: kind, label, context words, validator, separators allowed.
type DigitCheck = (
    &'static str,
    &'static str,
    &'static [&'static str],
    fn(&str) -> bool,
    bool,
);

/// National phone numbers without a `+` (the international form is in [`crate::pii`]):
/// RU `8 (9xx) ...`, US/CA `(xxx) xxx-xxxx`, FR `0x xx xx xx xx`, UK, DE, IT, ES, PL, TR.
/// Ambiguous shapes need a phone word on the line; `lang` (document language) picks the
/// country for shapes shared by several countries.
pub fn national_phones(text: &str, lang: &str) -> Vec<PhoneMatch> {
    let mut out: Vec<PhoneMatch> = Vec::new();
    for c in re_national().captures_iter(text) {
        let Some(m) = c.get(1) else { continue };
        let raw = m.as_str().trim_end_matches(|c: char| !c.is_ascii_digit());
        let (s, e) = (m.start(), m.start() + raw.len());
        if text[e..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c.is_alphabetic())
        {
            continue;
        }
        let d: String = raw.chars().filter(char::is_ascii_digit).collect();
        let groups = raw
            .split(|c: char| !c.is_ascii_digit())
            .filter(|g| !g.is_empty())
            .count();
        let bare = groups < 2 && !raw.starts_with('(');
        let ctx = near(text, s, e, PHONE_WORDS);
        // Ukrainian numbers: `0XX XXX XX XX`, `(0XX)XXX-XX-XX`, or a bare `0XXXXXXXXX` next to
        // a phone word.
        if d.len() == 10 && matches!(lang, "uk" | "ru" | "be" | "") && ua_code(&d) {
            let shaped = raw.starts_with('(') || ua_shape(raw);
            if ctx || (shaped && !bare) {
                if !out.iter().any(|p| p.start < e && s < p.end) {
                    out.push(PhoneMatch {
                        start: s,
                        end: e,
                        value: format!("+38{d}"),
                        country: "UA",
                    });
                }
                continue;
            }
        }
        if bare {
            continue; // a bare digit run is a number, not a phone
        }
        let pairs = raw.split([' ', '.']).all(|g| g.len() == 2) && d.len() == 10;
        let (country, value): (&'static str, String) =
            if d.len() == 11 && d.starts_with("89") && raw.contains('(') {
                ("RU", format!("+7{}", &d[1..]))
            } else if d.len() == 10
                && raw.starts_with('(')
                && !d.starts_with('0')
                && !d.starts_with('1')
            {
                ("US", format!("+1{d}"))
            } else if pairs && d.starts_with('0') && !d.starts_with("00") && ctx {
                ("FR", format!("+33{}", &d[1..]))
            } else if !ctx {
                continue;
            } else if d.len() == 11 && d.starts_with("05") && lang == "tr" {
                ("TR", format!("+90{}", &d[1..]))
            } else if d.len() == 11
                && d.starts_with('0')
                && (lang == "en" || lang == "und")
                && !d.starts_with("00")
            {
                ("GB", format!("+44{}", &d[1..]))
            } else if d.len() == 10
                && !d.starts_with('0')
                && !d.starts_with('1')
                && matches!(lang, "en" | "und")
            {
                ("US", format!("+1{d}"))
            } else if d.len() == 10 && d.starts_with('3') && lang == "it" {
                ("IT", format!("+39{d}"))
            } else if d.len() == 9
                && matches!(d.as_bytes()[0], b'6' | b'7' | b'8' | b'9')
                && lang == "es"
            {
                ("ES", format!("+34{d}"))
            } else if d.len() == 9 && lang == "pl" {
                ("PL", format!("+48{d}"))
            } else if (6..=12).contains(&(d.len() - 1))
                && d.starts_with('0')
                && !d.starts_with("00")
                && lang == "de"
            {
                ("DE", format!("+49{}", &d[1..]))
            } else if (7..=12).contains(&d.len()) {
                ("", d.clone())
            } else {
                continue;
            };
        if !out.iter().any(|p| p.start < e && s < p.end) {
            out.push(PhoneMatch {
                start: s,
                end: e,
                value,
                country,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(t: &str) -> Vec<&'static str> {
        scan_ids(t).into_iter().map(|h| h.kind).collect()
    }

    #[test]
    fn check_digits() {
        assert!(ru_inn_valid("7707083893"));
        assert!(ru_inn_valid("500100732259"));
        assert!(!ru_inn_valid("7707083894"));
        assert!(ru_snils_valid("11223344595"));
        assert!(!ru_snils_valid("11223344596"));
        assert!(ru_ogrn_valid("1027700132195"));
        assert!(pl_pesel_valid("44051401359"));
        assert!(!pl_pesel_valid("44051401358"));
        assert!(pl_nip_valid("1234563218"));
        assert!(de_steuer_id_valid("86095742719"));
        assert!(!de_steuer_id_valid("86095742718"));
        assert!(es_dni_valid("", "12345678", 'Z'));
        assert!(es_dni_valid("X", "1234567", 'L'));
        assert!(it_cf_valid("RSSMRA85T10A562S"));
        assert!(!it_cf_valid("RSSMRA85T10A562T"));
        assert!(iban_valid("DE89370400440532013000"));
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(!iban_valid("DE89370400440532013001"));
        assert!(fr_nir_valid(
            "1850775123456",
            &format!("{:02}", 97 - 1850775123456u64 % 97)
        ));
    }

    #[test]
    fn ids_need_context_or_strong_format() {
        assert_eq!(kinds("ИНН 500100732259"), ["ru_inn"]);
        assert!(kinds("Заказ 500100732259").is_empty());
        assert_eq!(kinds("СНИЛС 112-233-445 95"), ["ru_snils"]);
        assert_eq!(kinds("PESEL: 44051401359"), ["pl_pesel"]);
        assert_eq!(kinds("NIP 123-456-32-18"), ["pl_nip"]);
        assert_eq!(kinds("Steuer-ID 86095742719"), ["de_steuer_id"]);
        assert_eq!(kinds("SSN 123-45-6789"), ["us_ssn"]);
        assert!(kinds("Order 123-45-6789").is_empty());
        assert_eq!(kinds("NI number AB123456C"), ["uk_nino"]);
        assert_eq!(kinds("DNI 12345678Z"), ["es_dni"]);
        assert_eq!(kinds("CF: RSSMRA85T10A562S"), ["it_cf"]);
        assert_eq!(kinds("IBAN DE89 3704 0044 0532 0130 00 BIC"), ["iban"]);
        assert_eq!(kinds("Reisepass Nr. C01X00T47"), ["passport"]);
    }

    #[test]
    fn national_phone_shapes() {
        let p = national_phones("Тел.: 8 (912) 345-67-89", "ru");
        assert_eq!(p[0].value, "+79123456789");
        let p = national_phones("Call (415) 555-2671 today", "en");
        assert_eq!((p[0].country, p[0].value.as_str()), ("US", "+14155552671"));
        let p = national_phones("Tél. 01 23 45 67 89", "fr");
        assert_eq!(p[0].country, "FR");
        let p = national_phones("Telefon: 030 1234567", "de");
        assert_eq!(p[0].country, "DE");
        assert!(national_phones("Seite 12 von 30, Jahr 2024", "de").is_empty());
        assert!(national_phones("ISBN 978-3-16-148410-0", "en").is_empty());
    }
}
