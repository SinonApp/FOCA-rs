//! Contacts and identifiers in a document text, positioned by line so they can be linked to
//! the person named on the same line or in the same block.

use std::sync::OnceLock;

use regex::Regex;

use crate::content::natid;
use crate::emails;
use crate::pii::{self, PiiKind};

/// Contact or identifier kind: `phone`, `email`, `address`, `student_id`, `birth_date`,
/// `rnokpp`, `passport`, `iban`, `card`, `id_card`, `edrpou` or a [`natid`] kind
/// (`pl_pesel`, `ru_inn`, ...).
pub type ContactKind = &'static str;

/// A phone number found in the text.
#[derive(Clone, PartialEq, Eq)]
pub struct PhoneHit {
    /// E.164 (`+380501234567`) when known, otherwise the national digits; for text that was
    /// already masked at storage, the masked token.
    pub value: String,
    /// ISO country (`UA`, `US`, ...) or empty.
    pub country: &'static str,
    /// 1-based line.
    pub line: usize,
}

impl std::fmt::Debug for PhoneHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneHit")
            .field("value", &pii::pii_mask(&self.value))
            .field("country", &self.country)
            .field("line", &self.line)
            .finish()
    }
}

/// One contact positioned in the text.
#[derive(Debug, Clone)]
pub struct Contact {
    /// 0-based line index and byte column within the line.
    pub li: usize,
    pub col: usize,
    pub kind: ContactKind,
    /// Phone value or e-mail address (identifiers carry no value).
    pub value: Option<String>,
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("builtin contact regex")
}

fn re_dob() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?i)(?:дата народження|дата рождения|народився|народилася|родился|родилась|р\.\s?н\.|г\.\s?р\.|рік народження|date of birth|birth date|\bdob\b|d\.o\.b\.|geburtsdatum|\bgeb\.|né le|née le|date de naissance|fecha de nacimiento|data di nascita|data de nascimento|data urodzenia|datum narození|doğum tarihi|出生日期|生年月日|생년월일)[^\n\d]{0,25}(?:\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4}|\d{4}[./\-]\d{1,2}[./\-]\d{1,2}|\d{1,2}\s+\p{L}+\s+\d{4})")
    })
}

fn re_student() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?i)(?:залікової книжки|залікова книжка|зачетной книжки|зачетная книжка|студентськ\w* квит\w*|студенческ\w* билет\w*|student id|matrikelnummer|matrikel-nr|numer albumu|n° étudiant|numéro étudiant|matricola|学号|学籍番号|학번)[^\n]{0,30}?(?:№\s?)?([A-ZА-ЯІЇЄ]{0,3}\d{5,})")
    })
}

fn re_address() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?i)(?:^|[^\p{L}])(?:вул\.|вулиця|просп\.|проспект|бульв\.|бульвар|пров\.|провулок|ул\.|улица|street|st\.|avenue|ave\.|road|rd\.|straße|strasse|str\.|rue|boulevard|calle|avda\.|avenida|via|viale|ulica|ul\.|ulice|sokak|cad\.|caddesi)\s*[\p{L}'’\-. ]{2,40}?,?\s*(?:буд\.?|б\.|no\.?|nr\.?|№)?\s*\d+[\p{L}]?")
    })
}

fn re_masked_phone() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r"•{4,}\d{2}"))
}

/// Everything found, by line.
#[derive(Debug, Default)]
pub struct Contacts {
    pub list: Vec<Contact>,
    pub phones: Vec<PhoneHit>,
}

/// (line index, column) of a byte offset.
fn locate(starts: &[usize], off: usize) -> (usize, usize) {
    let li = match starts.binary_search(&off) {
        Ok(i) => i,
        Err(i) => i.saturating_sub(1),
    };
    (li, off - starts.get(li).copied().unwrap_or(0))
}

/// Scans `text` (whose `lines` are slices of it) in language `lang`. Only lines that can hold
/// a contact (four or more digits, `@`, a masked value or an e-mail obfuscation word) are fed
/// to the value scanners, which keeps digit-poor prose out of the regular expressions.
pub fn scan(_text: &str, lines: &[&str], lang: &str) -> Contacts {
    let mut c = Contacts::default();
    // Candidate lines joined into one buffer; `map[i]` = original line index of buffer line i.
    let mut buf = String::new();
    let mut map: Vec<usize> = Vec::new();
    let mut starts: Vec<usize> = Vec::new();
    for (li, l) in lines.iter().enumerate() {
        let digits = l.bytes().filter(u8::is_ascii_digit).count();
        if digits >= 4 || l.contains('•') {
            starts.push(buf.len());
            map.push(li);
            buf.push_str(l);
            buf.push('\n');
        }
    }
    let text = buf.as_str();
    let at = |off: usize| -> (usize, usize) {
        let (bi, col) = locate(&starts, off);
        (map.get(bi).copied().unwrap_or(0), col)
    };
    let push = |c: &mut Contacts, off: usize, kind: ContactKind, value: Option<String>| {
        let (li, col) = at(off);
        c.list.push(Contact {
            li,
            col,
            kind,
            value,
        });
    };
    let phone = |c: &mut Contacts, off: usize, value: String, country: &'static str| {
        let (li, _) = at(off);
        if !c.phones.iter().any(|p| p.value == value) {
            c.phones.push(PhoneHit {
                value: value.clone(),
                country,
                line: li + 1,
            });
        }
    };
    let mut phone_spans: Vec<(usize, usize)> = Vec::new();
    if !text.is_empty() {
        for h in pii::scan(text, "") {
            let kind: ContactKind = match h.kind {
                PiiKind::Phone => {
                    let v = h.value.expose().to_string();
                    let country = if v.starts_with("+380") { "UA" } else { "" };
                    phone_spans.push((h.start, h.end));
                    phone(&mut c, h.start, v.clone(), country);
                    push(&mut c, h.start, "phone", Some(v));
                    continue;
                }
                PiiKind::Rnokpp => "rnokpp",
                PiiKind::Edrpou => "edrpou",
                PiiKind::Iban => "iban",
                PiiKind::Card => "card",
                PiiKind::Passport => "passport",
                PiiKind::IdCard => "id_card",
                _ => continue,
            };
            push(&mut c, h.start, kind, None);
        }
        for p in natid::national_phones(text, lang) {
            if phone_spans.iter().any(|(s, e)| *s < p.end && p.start < *e) {
                continue;
            }
            phone(&mut c, p.start, p.value.clone(), p.country);
            push(&mut c, p.start, "phone", Some(p.value));
        }
        for h in natid::scan_ids(text) {
            push(&mut c, h.start, h.kind, None);
        }
        // Values masked at storage (`••••••••67`) still mark a phone next to a phone word.
        for m in re_masked_phone().find_iter(text) {
            let (bi, col) = locate(&starts, m.start());
            let line = &text[starts[bi]..];
            let before = line[..col].to_lowercase();
            if natid::PHONE_WORDS.iter().any(|w| before.contains(w)) {
                phone(&mut c, m.start(), m.as_str().to_string(), "");
                push(&mut c, m.start(), "phone", Some(m.as_str().to_string()));
            }
        }
        for m in re_dob().find_iter(text) {
            push(&mut c, m.start(), "birth_date", None);
        }
        for m in re_student().captures_iter(text) {
            if let Some(g) = m.get(1) {
                push(&mut c, g.start(), "student_id", None);
            }
        }
        for m in re_address().find_iter(text) {
            push(&mut c, m.start(), "address", None);
        }
    }
    for (li, l) in lines.iter().enumerate() {
        if !emails::may_hold_address(l) {
            continue;
        }
        for (col, addr) in emails::find_in_line(l) {
            c.list.push(Contact {
                li,
                col,
                kind: "email",
                value: Some(addr),
            });
        }
    }
    c.list.sort_by_key(|x| (x.li, x.col));
    c
}

impl Contacts {
    /// Kind counts over the whole text.
    pub fn counts(&self) -> Vec<(ContactKind, u32)> {
        let mut v: Vec<(ContactKind, u32)> = Vec::new();
        for x in &self.list {
            match v.iter_mut().find(|(k, _)| *k == x.kind) {
                Some((_, n)) => *n += 1,
                None => v.push((x.kind, 1)),
            }
        }
        v.sort();
        v
    }
}
