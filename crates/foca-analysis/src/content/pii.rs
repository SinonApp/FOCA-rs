//! Personal data and access markings in document text (`foca-analysis::pii`).
//!
//! Detectors validate check digits wherever an official algorithm exists, so a random run of
//! digits rarely passes:
//!
//! * RNOKPP / IPN (Ukrainian individual tax number): 10 digits, weighted mod 11 check digit;
//! * EDRPOU (legal entity code): 8 digits, weighted mod 11 check digit with the second pass;
//! * IBAN `UA`: 29 characters, ISO 13616 mod 97;
//! * payment cards: Luhn plus the issuer (BIN) range and the allowed length of the brand;
//! * passports: the old booklet (two Cyrillic letters + 6 digits) and the ID card (9 digits),
//!   accepted only next to a context word;
//! * phone numbers: `+380` / national mobile format and international E.164 with a `+`;
//! * access restriction markings (`ДСК`, `Для службового користування`, `Таємно`,
//!   `Confidential`, `Draft`, …) recognised only as a stamp line at the top or bottom of a
//!   page or block, never inside a sentence or before a series number (see
//!   [`crate::content::markings`]).
//!
//! Values are wrapped in [`SecretValue`]: `Debug`/`Display` print only the mask, the context
//! carries the value as `{{s:…}}` exactly like secrets, so the snapshot layer masks it the same
//! way. [`redact`] returns text with every secret and PII value already replaced by its mask
//! (for search snippets and any other place that bypasses the snapshot masking).

use std::sync::OnceLock;

use foca_core::{api::SecretValue, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::secrets;
pub use crate::secrets::mask_markers;

/// PII category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiKind {
    Rnokpp,
    Edrpou,
    Iban,
    Card,
    Passport,
    IdCard,
    Phone,
    /// Access restriction marking (not a personal value, kept unmasked in `detail`).
    Marking,
}

impl PiiKind {
    pub fn id(self) -> &'static str {
        match self {
            PiiKind::Rnokpp => "rnokpp",
            PiiKind::Edrpou => "edrpou",
            PiiKind::Iban => "iban",
            PiiKind::Card => "card",
            PiiKind::Passport => "passport",
            PiiKind::IdCard => "id_card",
            PiiKind::Phone => "phone",
            PiiKind::Marking => "marking",
        }
    }

    /// UI title of the proposed finding.
    pub fn title(self) -> &'static str {
        match self {
            PiiKind::Rnokpp => "РНОКПП (ІПН) физлица в документе",
            PiiKind::Edrpou => "Код ЄДРПОУ в документе",
            PiiKind::Iban => "Номер счёта IBAN в документе",
            PiiKind::Card => "Номер банковской карты в документе",
            PiiKind::Passport => "Серия и номер паспорта в документе",
            PiiKind::IdCard => "Номер ID-карты в документе",
            PiiKind::Phone => "Номер телефона в документе",
            PiiKind::Marking => "Гриф ограничения доступа в документе",
        }
    }

    /// Default severity (markings get theirs from the marking level).
    pub fn sev(self) -> Severity {
        match self {
            PiiKind::Card | PiiKind::Passport | PiiKind::IdCard => Severity::High,
            // High next to a person's name or with several values ([`summarize`]); an
            // organisation's own account (requisites) is low.
            PiiKind::Rnokpp | PiiKind::Iban => Severity::Medium,
            PiiKind::Edrpou => Severity::Info,
            PiiKind::Phone => Severity::Low,
            PiiKind::Marking => Severity::Medium,
        }
    }
}

/// How sure the detector is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Valid check digit only.
    Medium,
    /// Valid check digit (where applicable) and a context word nearby.
    High,
}

/// A detected PII value or marking. `value` and `context` are masked in `Debug`.
#[derive(Clone, PartialEq, Serialize)]
pub struct PiiHit {
    pub kind: PiiKind,
    pub title: String,
    pub sev: Severity,
    /// Normalised value (digits only for numbers, `UA…` without spaces for IBAN).
    pub value: SecretValue,
    /// Byte range of the raw match in the scanned text.
    pub start: usize,
    pub end: usize,
    /// The line with the value wrapped as `{{s:…}}` (masked by the UI like secrets).
    pub context: String,
    /// `place` or `place, строка N`.
    pub location: String,
    pub confidence: Confidence,
    /// Non-sensitive detail: card brand, IBAN bank code (MFO), the marking text.
    pub detail: Option<String>,
}

impl std::fmt::Debug for PiiHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiiHit")
            .field("kind", &self.kind)
            .field("sev", &self.sev)
            .field("value", &self.value)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("context", &self.masked_context())
            .field("location", &self.location)
            .field("confidence", &self.confidence)
            .field("detail", &self.detail)
            .finish()
    }
}

impl PiiHit {
    /// The context with the value replaced by its mask (for logs and plain reports).
    pub fn masked_context(&self) -> String {
        mask_markers(&self.context)
    }
}

/// Maximum text size scanned in one call; the rest is ignored (time budget on a phone).
pub const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;
/// Maximum hits returned per call.
pub const MAX_HITS: usize = 500;

fn re(p: &str) -> Regex {
    Regex::new(p).expect("builtin PII regex")
}

macro_rules! lazy_re {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| re($pat))
        }
    };
}

lazy_re!(re_iban, r"(?i)\bUA[ \u00a0]?\d{2}(?:[ \u00a0]?\d){25}\b");
lazy_re!(re_card, r"\b\d(?:[ \-]?\d){11,18}\b");
lazy_re!(re_d10, r"\b\d{10}\b");
lazy_re!(re_d8, r"\b\d{8}\b");
lazy_re!(
    re_passport,
    r"(?:^|[^\p{L}\p{N}])([АВЕІКМНОРСТХЮЯБГДЖЗЛПУФЦЧШЩЄЇҐ]{2})[ \u00a0]?(?:№[ \u00a0]?)?(\d{6})\b"
);
lazy_re!(re_d9, r"\b\d{9}\b");
lazy_re!(
    re_phone_ua,
    r"(?:\+[ \u00a0]?|\b)38[ \u00a0\-]?\(?0\d{2}\)?[ \u00a0\-]?\d{3}[ \u00a0\-]?\d{2}[ \u00a0\-]?\d{2}\b|(?:^|[^\d+])(\(?0(?:39|50|63|66|67|68|73|89|91|92|93|94|95|96|97|98|99)\)?[ \u00a0\-]\d{3}[ \u00a0\-]?\d{2}[ \u00a0\-]?\d{2})\b"
);
lazy_re!(
    re_phone_intl,
    r"\+[1-9]\d{0,2}(?:[ \u00a0.\-]?\(?\d{1,4}\)?){2,5}\b"
);

/// Finds PII values and access markings in `text`. `place` names the location; for
/// multi-line text the line number is appended.
pub fn scan(text: &str, place: &str) -> Vec<PiiHit> {
    scan_inner(text, place, true)
}

fn scan_inner(text: &str, place: &str, dedup: bool) -> Vec<PiiHit> {
    let text = clip(text, MAX_SCAN_BYTES);
    let mut out: Vec<PiiHit> = Vec::new();
    if text.len() < 3 {
        return out;
    }
    let lower = text.to_lowercase();
    let has_digits = text.bytes().any(|b| b.is_ascii_digit());
    let ctx = Ctx {
        text,
        place,
        multiline: text.contains('\n'),
        dedup,
    };
    if has_digits {
        iban(&ctx, &mut out);
        cards(&ctx, &mut out);
        rnokpp(&ctx, &mut out);
        edrpou(&ctx, &mut out);
        if lower.contains("паспорт")
            || lower.contains("passport")
            || lower.contains("серія")
            || lower.contains("серия")
            || IDCARD_WORDS.iter().any(|w| lower.contains(w))
        {
            passports(&ctx, &mut out);
        }
        phones(&ctx, &mut out);
    }
    markings(&ctx, &mut out);
    out.sort_by_key(|h| h.start);
    out.truncate(MAX_HITS);
    out
}

struct Ctx<'a> {
    text: &'a str,
    place: &'a str,
    multiline: bool,
    dedup: bool,
}

impl Ctx<'_> {
    fn overlaps(out: &[PiiHit], s: usize, e: usize) -> bool {
        out.iter().any(|h| h.start < e && s < h.end)
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &self,
        out: &mut Vec<PiiHit>,
        kind: PiiKind,
        s: usize,
        e: usize,
        value: String,
        confidence: Confidence,
        detail: Option<String>,
        sev: Option<Severity>,
    ) {
        if out.len() >= MAX_HITS || Self::overlaps(out, s, e) {
            return;
        }
        // One value, one hit per kind (disabled when collecting all occurrences to mask).
        if self.dedup
            && kind != PiiKind::Marking
            && out
                .iter()
                .any(|h| h.kind == kind && h.value.expose() == value)
        {
            return;
        }
        let location = if self.multiline {
            let line = self.text[..s].matches('\n').count() + 1;
            format!("{}, строка {line}", self.place)
        } else {
            self.place.to_string()
        };
        out.push(PiiHit {
            kind,
            title: kind.title().to_string(),
            sev: sev.unwrap_or(kind.sev()),
            value: SecretValue::new(value),
            start: s,
            end: e,
            context: if kind == PiiKind::Marking {
                line_of(self.text, s, e).trim().to_string()
            } else {
                secret_context(self.text, s, e)
            },
            location,
            confidence,
            detail,
        });
    }

    /// Lower-cased text of up to `n` characters before byte `s` (same line or the previous one).
    fn before(&self, s: usize, n: usize) -> String {
        let b = &self.text[..s];
        let start = b
            .char_indices()
            .rev()
            .nth(n.saturating_sub(1))
            .map(|(i, _)| i)
            .unwrap_or(0);
        b[start..].to_lowercase()
    }

    fn after(&self, e: usize, n: usize) -> String {
        let a = &self.text[e..];
        let end = a.char_indices().nth(n).map(|(i, _)| i).unwrap_or(a.len());
        a[..end].to_lowercase()
    }

    /// A person's full name within ~80 characters around the value.
    fn near_name(&self, s: usize, e: usize) -> bool {
        let mut a = s.saturating_sub(240);
        while !self.text.is_char_boundary(a) {
            a -= 1;
        }
        let mut b = (e + 240).min(self.text.len());
        while !self.text.is_char_boundary(b) {
            b += 1;
        }
        let around: String = {
            let before: String = self.text[a..s].chars().rev().take(80).collect();
            let after: String = self.text[e..b].chars().take(80).collect();
            before.chars().rev().collect::<String>() + " " + &after
        };
        re_person().is_match(&around)
    }

    fn near(&self, s: usize, e: usize, words: &[&str]) -> bool {
        let b = self.before(s, 60);
        let a = self.after(e, 20);
        words.iter().any(|w| b.contains(w) || a.contains(w))
    }
}

fn digits(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

fn dvec(s: &str) -> Vec<u32> {
    s.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| (b - b'0') as u32)
        .collect()
}

/// `true` when the match is glued to other digits or a decimal separator (part of a longer
/// number, an amount or a version).
fn glued(text: &str, s: usize, e: usize) -> bool {
    let prev = text[..s].chars().next_back();
    let prev2 = text[..s].chars().rev().nth(1);
    let next = text[e..].chars().next();
    let next2 = text[e..].chars().nth(1);
    let digitish = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
    digitish(prev)
        || digitish(next)
        || (matches!(prev, Some('.' | ',' | '-' | '/')) && digitish(prev2))
        || (matches!(next, Some('.' | ',' | '-' | '/')) && digitish(next2))
}

// ---------------- Check digits ----------------

/// RNOKPP check digit (State Tax Service algorithm): weights `-1 5 7 9 4 6 10 5 7`,
/// `(Σ mod 11) mod 10`.
pub fn rnokpp_valid(s: &str) -> bool {
    let d = dvec(s);
    if d.len() != 10 || s.len() != 10 {
        return false;
    }
    const W: [i64; 9] = [-1, 5, 7, 9, 4, 6, 10, 5, 7];
    let sum: i64 = W.iter().zip(&d).map(|(w, x)| w * *x as i64).sum();
    (sum.rem_euclid(11) % 10) as u32 == d[9]
}

/// EDRPOU check digit: weights `1..7` (or `7 1..6` for codes in 30000000..60000000), mod 11;
/// on remainder 10 the weights are increased by 2 and the remainder 10 becomes 0.
pub fn edrpou_valid(s: &str) -> bool {
    let d = dvec(s);
    if d.len() != 8 || s.len() != 8 {
        return false;
    }
    let code: u32 = s.parse().unwrap_or(0);
    let base: [u32; 7] = if (30_000_000..=60_000_000).contains(&code) {
        [7, 1, 2, 3, 4, 5, 6]
    } else {
        [1, 2, 3, 4, 5, 6, 7]
    };
    let sum = |add: u32| -> u32 { base.iter().zip(&d).map(|(w, x)| (w + add) * x).sum() };
    let mut r = sum(0) % 11;
    if r == 10 {
        r = sum(2) % 11;
        if r == 10 {
            r = 0;
        }
    }
    r == d[7]
}

/// ISO 13616 IBAN check (mod 97 == 1) for the `UA` format (29 characters).
pub fn iban_ua_valid(s: &str) -> bool {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let s = s.to_ascii_uppercase();
    if s.len() != 29 || !s.starts_with("UA") || !s[2..].bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    iban_mod97(&s) == 1
}

fn iban_mod97(s: &str) -> u32 {
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut r: u32 = 0;
    for c in rearranged.chars() {
        let v = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => c as u32 - 'A' as u32 + 10,
            _ => return 0,
        };
        r = if v >= 10 {
            (r * 100 + v) % 97
        } else {
            (r * 10 + v) % 97
        };
    }
    r
}

pub fn luhn_valid(s: &str) -> bool {
    let d = dvec(s);
    if d.len() < 12 {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            if i % 2 == 1 {
                let y = x * 2;
                if y > 9 {
                    y - 9
                } else {
                    y
                }
            } else {
                x
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Card brand by issuer range and length; `None` if the number fits no known brand.
pub fn card_brand(num: &str) -> Option<&'static str> {
    let n = num.len();
    let p = |k: usize| -> u32 { num.get(..k).and_then(|x| x.parse().ok()).unwrap_or(0) };
    let brand = if num.starts_with('4') && matches!(n, 13 | 16 | 19) {
        "Visa"
    } else if ((51..=55).contains(&p(2)) || (2221..=2720).contains(&p(4))) && n == 16 {
        "Mastercard"
    } else if matches!(p(2), 34 | 37) && n == 15 {
        "American Express"
    } else if p(4) == 9804 && n == 16 {
        "ПРОСТІР"
    } else if (2200..=2204).contains(&p(4)) && n == 16 {
        "Mir"
    } else if (3528..=3589).contains(&p(4)) && (16..=19).contains(&n) {
        "JCB"
    } else if (p(4) == 6011 || p(2) == 65 || (644..=649).contains(&p(3))) && (16..=19).contains(&n)
    {
        "Discover"
    } else if p(2) == 62 && (16..=19).contains(&n) {
        "UnionPay"
    } else if (p(2) == 50 || (56..=69).contains(&p(2))) && (12..=19).contains(&n) {
        "Maestro"
    } else {
        return None;
    };
    Some(brand)
}

// ---------------- Detectors ----------------

const RNOKPP_WORDS: &[&str] = &[
    "рнокпп",
    "іпн",
    "инн",
    "ідентифікаційний номер",
    "идентификационный номер",
    "ідентифікаційний код",
    "податковий номер",
    "реєстраційний номер облікової картки",
    "tax id",
    "taxpayer",
    "tin",
];
const EDRPOU_WORDS: &[&str] = &[
    "єдрпоу",
    "едрпоу",
    "edrpou",
    "usreou",
    "код юридичної особи",
];
const PASSPORT_WORDS: &[&str] = &["паспорт", "passport", "серія", "серия"];
const IDCARD_WORDS: &[&str] = &[
    "id-карт",
    "id карт",
    "ід-карт",
    "id-card",
    "id card",
    "паспорт громадянина україни",
    "номер документа",
    "документ №",
];
const CARD_WORDS: &[&str] = &[
    "карт",
    "card",
    "visa",
    "mastercard",
    "№ рахунку",
    "cvv",
    "cvc",
    "термін дії",
    "срок действия",
    "expiry",
    "exp.",
    "valid thru",
];
/// Words of an organisation's requisites (its own account in a licence or invoice).
const ORG_WORDS: &[&str] = &[
    "єдрпоу",
    "едрпоу",
    "тов ",
    "університет",
    "университет",
    "установ",
    "заклад",
    "підприємств",
    "предприят",
    "казначейств",
    "дксу",
    "реквізит",
    "реквизит",
    "юридична адреса",
    "юридический адрес",
];
/// A person's full name: surname with initials, three capitalised words, or a ПІБ label.
fn re_person() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?:\b(?:ПІБ|ФІО|ФИО|П\.І\.Б\.|Ф\.И\.О\.)|[А-ЯІЇЄҐ][а-яіїєґ'’]{2,}\s+[А-ЯІЇЄҐ]\.\s?[А-ЯІЇЄҐ]\.|[А-ЯІЇЄҐ]\.\s?[А-ЯІЇЄҐ]\.\s?[А-ЯІЇЄҐ][а-яіїєґ'’]{2,}|[А-ЯІЇЄҐ][а-яіїєґ'’]{2,}\s+[А-ЯІЇЄҐ][а-яіїєґ'’]{2,}\s+[А-ЯІЇЄҐ][а-яіїєґ'’]{2,}(?:вич|вна|ович|івна|ївна|евич|евна|ич|на)\b|[А-ЯІЇЄҐ][а-яіїєґ'’]{2,}\s+[А-ЯІЇЄҐ][а-яіїєґ'’]+(?:енко|ук|юк|чук|ський|цький|ська|цька|ов|ова|ев|ева|ін|іна|ин|ина|як|ко)\b)")
    })
}
const PHONE_WORDS: &[&str] = &[
    "тел", "моб", "phone", "tel", "факс", "fax", "viber", "telegram",
];

fn iban(c: &Ctx, out: &mut Vec<PiiHit>) {
    for m in re_iban().find_iter(c.text) {
        let v: String = m
            .as_str()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_uppercase();
        if iban_ua_valid(&v) {
            let mfo = v[4..10].to_string();
            let sev = if c.near_name(m.start(), m.end()) {
                Some(Severity::High)
            } else if c.near(m.start(), m.end(), ORG_WORDS) {
                Some(Severity::Low)
            } else {
                None
            };
            c.push(
                out,
                PiiKind::Iban,
                m.start(),
                m.end(),
                v,
                Confidence::High,
                Some(format!("МФО {mfo}")),
                sev,
            );
        }
    }
}

fn cards(c: &Ctx, out: &mut Vec<PiiHit>) {
    for m in re_card().find_iter(c.text) {
        let raw = m.as_str();
        // Separators must be consistent: none, only spaces or only dashes.
        if raw.contains(' ') && raw.contains('-') {
            continue;
        }
        if glued(c.text, m.start(), m.end()) {
            continue;
        }
        let num = digits(raw);
        if !(12..=19).contains(&num.len()) || num.bytes().all(|b| b == num.as_bytes()[0]) {
            continue;
        }
        if !luhn_valid(&num) {
            continue;
        }
        let Some(brand) = card_brand(&num) else {
            continue;
        };
        // Card context: a card word, CVV or expiry nearby, or the printed 4x4 grouping.
        // Without it a lone Luhn-valid number is dropped from the findings ([`summarize`]),
        // still masked.
        let grouped =
            raw.len() == 19 && raw.split([' ', '-']).filter(|g| g.len() == 4).count() == 4;
        let conf = if grouped || c.near(m.start(), m.end(), CARD_WORDS) {
            Confidence::High
        } else {
            Confidence::Medium
        };
        c.push(
            out,
            PiiKind::Card,
            m.start(),
            m.end(),
            num,
            conf,
            Some(brand.to_string()),
            None,
        );
    }
}

fn rnokpp(c: &Ctx, out: &mut Vec<PiiHit>) {
    for m in re_d10().find_iter(c.text) {
        let v = m.as_str();
        if glued(c.text, m.start(), m.end()) || !rnokpp_valid(v) {
            continue;
        }
        if c.text[..m.start()].ends_with('+') {
            continue;
        }
        let ctx = c.near(m.start(), m.end(), RNOKPP_WORDS);
        // Without a context word demand a plausible birth date: the first five digits are
        // days since 1899-12-31, so a leading zero (born before 1927) or a phone-like
        // `0XX…` is rejected, as is a date in the future (> ~2026).
        if !ctx {
            let days: u32 = v[..5].parse().unwrap_or(0);
            if !(10_000..=46_500).contains(&days) || c.near(m.start(), m.end(), PHONE_WORDS) {
                continue;
            }
        }
        c.push(
            out,
            PiiKind::Rnokpp,
            m.start(),
            m.end(),
            v.to_string(),
            if ctx {
                Confidence::High
            } else {
                Confidence::Medium
            },
            None,
            c.near_name(m.start(), m.end()).then_some(Severity::High),
        );
    }
}

fn edrpou(c: &Ctx, out: &mut Vec<PiiHit>) {
    for m in re_d8().find_iter(c.text) {
        let v = m.as_str();
        if glued(c.text, m.start(), m.end()) || !edrpou_valid(v) {
            continue;
        }
        // Eight digits are everywhere (dates, amounts): the context word is mandatory.
        if !c.near(m.start(), m.end(), EDRPOU_WORDS) {
            continue;
        }
        c.push(
            out,
            PiiKind::Edrpou,
            m.start(),
            m.end(),
            v.to_string(),
            Confidence::High,
            None,
            None,
        );
    }
}

fn passports(c: &Ctx, out: &mut Vec<PiiHit>) {
    for cap in re_passport().captures_iter(c.text) {
        let (Some(ser), Some(num)) = (cap.get(1), cap.get(2)) else {
            continue;
        };
        if glued(c.text, num.start(), num.end()) {
            continue;
        }
        if !c.near(ser.start(), num.end(), PASSPORT_WORDS) {
            continue;
        }
        c.push(
            out,
            PiiKind::Passport,
            ser.start(),
            num.end(),
            format!("{}{}", ser.as_str(), num.as_str()),
            Confidence::High,
            None,
            None,
        );
    }
    for m in re_d9().find_iter(c.text) {
        if glued(c.text, m.start(), m.end()) {
            continue;
        }
        if !c.near(m.start(), m.end(), IDCARD_WORDS) {
            continue;
        }
        c.push(
            out,
            PiiKind::IdCard,
            m.start(),
            m.end(),
            m.as_str().to_string(),
            Confidence::High,
            None,
            None,
        );
    }
}

fn phones(c: &Ctx, out: &mut Vec<PiiHit>) {
    for cap in re_phone_ua().captures_iter(c.text) {
        let m = cap.get(1).or_else(|| cap.get(0)).expect("match");
        let (s, e) = (m.start(), m.end());
        if glued(c.text, s, e) {
            continue;
        }
        let mut d = digits(m.as_str());
        if d.len() == 10 {
            d = format!("38{d}");
        }
        if d.len() != 12 {
            continue;
        }
        let conf = if c.near(s, e, PHONE_WORDS) {
            Confidence::High
        } else {
            Confidence::Medium
        };
        c.push(out, PiiKind::Phone, s, e, format!("+{d}"), conf, None, None);
    }
    for m in re_phone_intl().find_iter(c.text) {
        let raw = m.as_str();
        let d = digits(raw);
        if d.starts_with("380") || !(8..=15).contains(&d.len()) || glued(c.text, m.start(), m.end())
        {
            continue;
        }
        // A bare `+` followed by digits with dots is more likely arithmetic or a version.
        if raw.contains('.') && !c.near(m.start(), m.end(), PHONE_WORDS) {
            continue;
        }
        let conf = if c.near(m.start(), m.end(), PHONE_WORDS) {
            Confidence::High
        } else {
            Confidence::Medium
        };
        c.push(
            out,
            PiiKind::Phone,
            m.start(),
            m.end(),
            format!("+{d}"),
            conf,
            None,
            None,
        );
    }
}

fn line_of(text: &str, s: usize, e: usize) -> &str {
    let ls = text[..s].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let le = text[e..].find('\n').map(|i| e + i).unwrap_or(text.len());
    &text[ls..le]
}

fn markings(c: &Ctx, out: &mut Vec<PiiHit>) {
    for m in crate::content::markings::find(c.text) {
        c.push(
            out,
            PiiKind::Marking,
            m.start,
            m.end,
            m.label.to_string(),
            Confidence::High,
            Some(m.label.to_string()),
            Some(m.sev),
        );
    }
}

// ---------------- Context and redaction ----------------

fn clip(t: &str, max: usize) -> &str {
    if t.len() <= max {
        return t;
    }
    let mut end = max;
    while !t.is_char_boundary(end) {
        end -= 1;
    }
    &t[..end]
}

/// The line around the match with the value wrapped as `{{s:…}}`, 60 characters each side.
fn secret_context(text: &str, s: usize, e: usize) -> String {
    let line = line_of(text, s, e);
    let ls = s - (line.as_ptr() as usize - text.as_ptr() as usize);
    let le = ls + (e - s);
    let before: String = {
        let b = &line[..ls];
        let n = b.chars().count();
        b.chars().skip(n.saturating_sub(60)).collect()
    };
    let after: String = line[le..].chars().take(60).collect();
    format!(
        "{}{{{{s:{}}}}}{}",
        before.trim_start(),
        foca_core::api::escape_secret_marker(&text[s..e]),
        after.trim_end()
    )
}

fn secrets_mask(v: &str) -> String {
    foca_core::api::mask(v)
}

/// A sensitive byte range of a text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    /// `secret:<rule>` or `pii:<kind>`.
    pub label: String,
}

/// Byte ranges of secrets (built-in rules) and PII values (markings excluded) in `text`,
/// sorted and non-overlapping.
pub fn sensitive_spans(text: &str) -> Vec<Span> {
    let text = clip(text, MAX_SCAN_BYTES);
    let mut spans: Vec<Span> = Vec::new();
    for h in secrets::Rules::builtin().scan(text, "") {
        let v = h.value.expose();
        if v.is_empty() {
            continue;
        }
        let mut from = 0;
        while let Some(i) = text[from..].find(v) {
            let s = from + i;
            spans.push(Span {
                start: s,
                end: s + v.len(),
                label: format!("secret:{}", h.rule),
            });
            from = s + v.len();
        }
    }
    for h in scan_inner(text, "", false) {
        if h.kind != PiiKind::Marking {
            spans.push(Span {
                start: h.start,
                end: h.end,
                label: format!("pii:{}", h.kind.id()),
            });
        }
    }
    spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
    let mut merged: Vec<Span> = Vec::new();
    for s in spans {
        match merged.last_mut() {
            Some(l) if s.start < l.end => l.end = l.end.max(s.end),
            _ => merged.push(s),
        }
    }
    merged
}

/// Text with every secret and PII value replaced by `{{s:<mask>}}`; returns the text and the
/// labels of the masked ranges.
pub fn redact(text: &str) -> (String, Vec<String>) {
    let spans = sensitive_spans(text);
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    let mut labels = Vec::new();
    for s in &spans {
        out.push_str(&text[at..s.start]);
        out.push_str("{{s:");
        out.push_str(&secrets_mask(&text[s.start..s.end]));
        out.push_str("}}");
        at = s.end;
        labels.push(s.label.clone());
    }
    out.push_str(&text[at..]);
    (out, labels)
}

// ---------------- Storage sanitizing ----------------

/// Mask of a stored PII value: bullets with the last two characters (`••••••••90`).
pub fn pii_mask(v: &str) -> String {
    let chars: Vec<char> = v.chars().filter(|c| !c.is_whitespace()).collect();
    if chars.len() <= 4 {
        return "••••".into();
    }
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{}{tail}", "•".repeat((chars.len() - 2).min(10)))
}

/// Kinds whose values are personal and are masked before storage (EDRPOU is a public
/// register code, markings are not values).
fn masked_kind(k: PiiKind) -> bool {
    !matches!(k, PiiKind::Edrpou | PiiKind::Marking)
}

/// Replaces every `{{s:value}}` marker of a PII context with the storage mask.
fn context_masked(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("{{s:") {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 4..];
        match foca_core::api::find_secret_marker_end(tail) {
            Some(j) => {
                let raw = foca_core::api::unescape_secret_marker(&tail[..j]);
                out.push_str(&pii_mask(&raw));
                rest = &tail[j + 2..];
            }
            None => {
                out.push_str("••••");
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// The hit context safe for storage, reports and logs: personal values masked, markings and
/// EDRPOU kept.
pub fn safe_context(h: &PiiHit) -> String {
    if masked_kind(h.kind) {
        context_masked(&h.context)
    } else {
        h.context.replace("{{s:", "").replace("}}", "")
    }
}

lazy_re!(re_ua_ident, r"\b(?:TINUA|PNOUA|IDCUA|PASUA)-?(\d{6,})");

/// Masks semantics identifiers of Ukrainian qualified certificates (`TINUA-<РНОКПП>`,
/// `PNOUA-`, `IDCUA-`, `PASUA-`) wherever they appear (raw certificate bytes in a text layer,
/// subject strings), regardless of check digits.
fn mask_ua_idents(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains("UA") {
        return std::borrow::Cow::Borrowed(text);
    }
    re_ua_ident().replace_all(text, |c: &regex::Captures| {
        let all = c.get(0).map(|m| m.as_str()).unwrap_or("");
        let d = c.get(1).map(|m| m.as_str()).unwrap_or("");
        format!("{}{}", &all[..all.len() - d.len()], pii_mask(d))
    })
}

/// `text` with every personal value (see [`PiiKind`], except EDRPOU and markings) replaced by
/// [`pii_mask`], plus all hits (including markings and EDRPOU).
pub fn mask_pii(text: &str, place: &str) -> (String, Vec<PiiHit>) {
    let (out, hits) = mask_with_samples(text, place);
    (out, hits.into_iter().map(|(h, _)| h).collect())
}

/// Like [`mask_pii`], each hit paired with a sample line cut from the masked text (so other
/// values on the same line are masked too).
fn mask_with_samples(text: &str, place: &str) -> (String, Vec<(PiiHit, String)>) {
    let pre = mask_ua_idents(text);
    let text: &str = &pre;
    let all_hits = scan_inner(text, place, false);
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    let mut unique: Vec<(PiiHit, (usize, usize))> = Vec::new();
    let mut seen_keys: Vec<(PiiKind, String)> = Vec::new();
    for h in all_hits {
        if h.start < at || h.end > text.len() {
            continue;
        }
        out.push_str(&text[at..h.start]);
        let s = out.len();
        if masked_kind(h.kind) {
            out.push_str(&pii_mask(&text[h.start..h.end]));
        } else {
            out.push_str(&text[h.start..h.end]);
        }
        let e = out.len();
        at = h.end;
        let is_first = h.kind == PiiKind::Marking || {
            let key = (h.kind, h.value.expose().to_string());
            if seen_keys.contains(&key) {
                false
            } else {
                seen_keys.push(key);
                true
            }
        };
        if is_first {
            unique.push((h, (s, e)));
        }
    }
    out.push_str(&text[at..]);
    let samples = unique
        .into_iter()
        .map(|(h, (s, e))| {
            let line = line_of(&out, s, e);
            let ls = s - (line.as_ptr() as usize - out.as_ptr() as usize);
            let le = ls + (e - s);
            let before: String = {
                let b = &line[..ls];
                let n = b.chars().count();
                b.chars().skip(n.saturating_sub(60)).collect()
            };
            let after: String = line[le..].chars().take(60).collect();
            let sample = format!(
                "{}{}{}",
                before.trim_start(),
                &line[ls..le],
                after.trim_end()
            );
            (h, sample)
        })
        .collect();
    (out, samples)
}

fn summarize(hits: &[(PiiHit, String)], into: &mut Vec<foca_core::PiiFound>) {
    // A lone card-like number without card context is not reported (still masked).
    let cards: Vec<&PiiHit> = hits
        .iter()
        .map(|(h, _)| h)
        .filter(|h| h.kind == PiiKind::Card)
        .collect();
    let mut card_values: Vec<&str> = cards.iter().map(|h| h.value.expose()).collect();
    card_values.sort_unstable();
    card_values.dedup();
    let drop_cards =
        card_values.len() < 2 && cards.iter().all(|h| h.confidence == Confidence::Medium);
    // Several personal account or tax numbers (not an organisation's requisites): high.
    let several = |k: PiiKind| {
        let mut v: Vec<&str> = hits
            .iter()
            .filter(|(h, _)| h.kind == k && h.sev != Severity::Low)
            .map(|(h, _)| h.value.expose())
            .collect();
        v.sort_unstable();
        v.dedup();
        v.len() >= 2
    };
    let (many_iban, many_rnokpp) = (several(PiiKind::Iban), several(PiiKind::Rnokpp));
    // A state secret stamp becomes Critical only next to real personal values.
    let personal = hits.iter().any(|(h, _)| {
        !matches!(h.kind, PiiKind::Marking | PiiKind::Edrpou | PiiKind::Phone)
            && !(h.kind == PiiKind::Card && drop_cards)
    });
    for (h, sample) in hits {
        if h.kind == PiiKind::Card && drop_cards {
            continue;
        }
        let kind = h.kind.id();
        let i = match into.iter().position(|p| p.kind == kind) {
            Some(i) => i,
            None => {
                into.push(foca_core::PiiFound {
                    kind: kind.into(),
                    sev: h.sev,
                    location: h.location.clone(),
                    ..Default::default()
                });
                into.len() - 1
            }
        };
        let p = &mut into[i];
        p.count += 1;
        let sev = match h.kind {
            PiiKind::Iban if many_iban && h.sev != Severity::Low => Severity::High,
            PiiKind::Rnokpp if many_rnokpp => Severity::High,
            PiiKind::Marking if personal && h.sev == Severity::High => Severity::Critical,
            _ => h.sev,
        };
        if p.count == 1 || sev < p.sev {
            p.sev = sev;
        }
        if p.samples.len() < 3 {
            let c: String = sample.chars().take(160).collect();
            if !p.samples.contains(&c) {
                p.samples.push(c);
            }
        }
        if let Some(d) = &h.detail {
            if p.details.len() < 5 && !p.details.contains(d) {
                p.details.push(d.clone());
            }
        }
    }
}

fn walk_strings(
    v: &mut serde_json::Value,
    place: &str,
    hits: &mut Vec<(PiiHit, String)>,
    budget: &mut usize,
) -> bool {
    match v {
        serde_json::Value::String(s) => {
            if s.len() < 6 || *budget == 0 {
                return false;
            }
            *budget = budget.saturating_sub(s.len());
            let (masked, h) = mask_with_samples(s, place);
            let changed = masked != *s;
            if !h.is_empty() || changed {
                hits.extend(h);
                *s = masked;
                changed
            } else {
                false
            }
        }
        serde_json::Value::Array(a) => {
            let mut changed = false;
            for x in a {
                changed |= walk_strings(x, place, hits, budget);
            }
            changed
        }
        serde_json::Value::Object(o) => {
            let mut changed = false;
            for (k, x) in o.iter_mut() {
                // Map entries (`fields`, `custom`, `xmp`) are named by their key.
                let p = if place.is_empty()
                    || matches!(place, "поле fields" | "поле custom" | "поле xmp")
                {
                    format!("поле {k}")
                } else {
                    place.to_string()
                };
                changed |= walk_strings(x, &p, hits, budget);
            }
            changed
        }
        _ => false,
    }
}

/// Prepares a parsed document for storage: scans the text and every metadata string for
/// personal data, stores the masked summary in `Metadata::pii` and masks the personal values
/// in both the text and the metadata. Full values never reach the project database, the
/// search index, reports or logs.
pub fn sanitize(
    meta: &foca_core::Metadata,
    text: Option<&str>,
) -> (foca_core::Metadata, Option<String>) {
    let mut found: Vec<foca_core::PiiFound> = Vec::new();
    let text_out = text.map(|t| {
        let (masked, hits) = mask_with_samples(t, "текст");
        summarize(&hits, &mut found);
        masked
    });
    let mut meta_out = meta.clone();
    meta_out.pii.clear();
    if let Ok(mut v) = serde_json::to_value(&meta_out) {
        // Thumbnails and binary-ish data are not text.
        if let Some(o) = v.as_object_mut() {
            o.remove("thumbnail");
        }
        let mut hits = Vec::new();
        let mut budget = MAX_SCAN_BYTES;
        let changed = walk_strings(&mut v, "", &mut hits, &mut budget);
        if changed || !hits.is_empty() {
            summarize(&hits, &mut found);
            if let Some(o) = v.as_object_mut() {
                if let Some(t) = serde_json::to_value(&meta.thumbnail)
                    .ok()
                    .filter(|t| !t.is_null())
                {
                    o.insert("thumbnail".into(), t);
                }
            }
            if let Ok(m) = serde_json::from_value::<foca_core::Metadata>(v) {
                meta_out = m;
            }
        }
    }
    meta_out.pii = found;
    (meta_out, text_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a synthetic RNOKPP with a valid check digit from 9 leading digits.
    pub(crate) fn mk_rnokpp(p: &str) -> String {
        for d in 0..10 {
            let s = format!("{p}{d}");
            if rnokpp_valid(&s) {
                return s;
            }
        }
        unreachable!()
    }

    pub(crate) fn mk_edrpou(p: &str) -> Option<String> {
        (0..10).map(|d| format!("{p}{d}")).find(|s| edrpou_valid(s))
    }

    /// Builds a synthetic UA IBAN with valid check digits (MFO 300001 is a placeholder).
    pub(crate) fn mk_iban(bban: &str) -> String {
        assert_eq!(bban.len(), 25);
        let probe = format!("UA00{bban}");
        let r = iban_mod97(&probe);
        let check = 98 - r;
        format!("UA{check:02}{bban}")
    }

    fn kinds(t: &str) -> Vec<PiiKind> {
        scan(t, "текст").into_iter().map(|h| h.kind).collect()
    }

    fn found(t: &str) -> Vec<(String, Severity)> {
        let m = foca_core::Metadata::default();
        sanitize(&m, Some(t))
            .0
            .pii
            .into_iter()
            .map(|p| (p.kind, p.sev))
            .collect()
    }

    #[test]
    fn card_numbers_need_context_or_several_values() {
        assert!(found("Номер замовлення 4111111111111111 від 12.03").is_empty());
        let k = |t: &str| found(t).into_iter().any(|(k, _)| k == "card");
        assert!(k("Картка: 4111111111111111"));
        assert!(k("Номер 4111 1111 1111 1111"));
        assert!(k("4111111111111111 та 5500000000000004"));
    }

    #[test]
    fn iban_and_rnokpp_severity_by_context() {
        let iban = mk_iban("3052990000026007233566001");
        let sev = |t: &str, kind: &str| {
            found(t)
                .into_iter()
                .find(|(k, _)| k == kind)
                .map(|(_, s)| s)
        };
        assert_eq!(
            sev(&format!("Рахунок {iban}"), "iban"),
            Some(Severity::Medium)
        );
        assert_eq!(
            sev(
                &format!("ТОВ «Приклад», код ЄДРПОУ 12345678, р/р {iban}"),
                "iban"
            ),
            Some(Severity::Low)
        );
        assert_eq!(
            sev(&format!("Отримувач: Іван Петренко, рахунок {iban}"), "iban"),
            Some(Severity::High)
        );
        let iban2 = mk_iban("3052990000026007233566002");
        assert_eq!(
            sev(&format!("Рахунок {iban}\nРахунок {iban2}"), "iban"),
            Some(Severity::High)
        );
        let r = mk_rnokpp("312456789");
        assert_eq!(
            sev(&format!("РНОКПП {r}"), "rnokpp"),
            Some(Severity::Medium)
        );
        assert_eq!(
            sev(&format!("Петренко І. П., РНОКПП {r}"), "rnokpp"),
            Some(Severity::High)
        );
    }

    #[test]
    fn check_digit_algorithms() {
        let r = mk_rnokpp("312456789");
        assert!(rnokpp_valid(&r));
        let mut bad = r.clone().into_bytes();
        bad[9] = b'0' + ((bad[9] - b'0' + 1) % 10);
        assert!(!rnokpp_valid(std::str::from_utf8(&bad).unwrap()));
        // Published sample codes of the EDRPOU algorithm.
        assert!(edrpou_valid("32855961"));
        assert!(edrpou_valid("00032129"));
        assert!(!edrpou_valid("32855962"));
        let iban = mk_iban("3000010000026007233566001");
        assert!(iban_ua_valid(&iban), "{iban}");
        assert!(!iban_ua_valid(&iban.replace("UA", "UB")));
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
        assert_eq!(card_brand("4111111111111111"), Some("Visa"));
        assert_eq!(card_brand("5500000000000004"), Some("Mastercard"));
        assert_eq!(card_brand("378282246310005"), Some("American Express"));
        assert_eq!(card_brand("9111111111111111"), None);
    }

    #[test]
    fn detects_synthetic_pii() {
        let r = mk_rnokpp("345678901");
        let e = mk_edrpou("3400000").unwrap();
        let iban = mk_iban("3000010000026007233566001");
        let spaced = format!(
            "{} {} {} {} {} {} {} {}",
            &iban[..4],
            &iban[4..8],
            &iban[8..12],
            &iban[12..16],
            &iban[16..20],
            &iban[20..24],
            &iban[24..28],
            &iban[28..]
        );
        let t = format!(
            "Тестова Особа, РНОКПП {r}\nТОВ «Приклад», код ЄДРПОУ {e}\nIBAN: {spaced}\n\
             Картка 4111 1111 1111 1111, тел. +38 (050) 123-45-67\n\
             Паспорт серія КМ 123456, ID-картка № 001234567\nPhone: +1 415 555 2671"
        );
        let hits = scan(&t, "текст");
        let k: Vec<PiiKind> = hits.iter().map(|h| h.kind).collect();
        for want in [
            PiiKind::Rnokpp,
            PiiKind::Edrpou,
            PiiKind::Iban,
            PiiKind::Card,
            PiiKind::Phone,
            PiiKind::Passport,
            PiiKind::IdCard,
        ] {
            assert!(k.contains(&want), "{want:?} missing in {k:?}");
        }
        assert_eq!(k.iter().filter(|x| **x == PiiKind::Phone).count(), 2);
        let card = hits.iter().find(|h| h.kind == PiiKind::Card).unwrap();
        assert_eq!(card.value.expose(), "4111111111111111");
        assert_eq!(card.detail.as_deref(), Some("Visa"));
        assert_eq!(card.location, "текст, строка 4");
        let ib = hits.iter().find(|h| h.kind == PiiKind::Iban).unwrap();
        assert_eq!(ib.value.expose(), iban);
        assert_eq!(ib.detail.as_deref(), Some("МФО 300001"));
        // Values never leak through Debug/Display.
        let dbg = format!("{hits:?}");
        assert!(!dbg.contains("4111111111111111") && !dbg.contains(&r));
        assert!(!card.masked_context().contains("4111 1111 1111 1111"));
        assert!(card.context.contains("{{s:4111 1111 1111 1111}}"));
    }

    #[test]
    fn false_positives_suppressed() {
        let r = mk_rnokpp("345678901");
        let e = mk_edrpou("3400000").unwrap();
        // EDRPOU without the context word, dates, amounts, versions, order numbers.
        assert!(kinds(&format!("Номер замовлення {e}, дата 20240115")).is_empty());
        assert!(kinds("Сума 4111111111111111.50 грн").is_empty());
        assert!(kinds("Версія 1.2.3.4111111111111111").is_empty());
        // A longer digit run containing a valid number.
        assert!(kinds(&format!("рахунок 9{r}9")).is_empty());
        // Luhn-valid but no brand.
        assert!(kinds("номер 9111 1111 1111 1111").is_empty());
        // Mixed separators.
        assert!(!kinds("4111 1111-1111 1111").contains(&PiiKind::Card));
        // Passport-like letters + digits without context.
        assert!(kinds("Об'єкт КМ 123456 на складі").is_empty());
        // 9 digits without ID-card context.
        assert!(kinds("Інв. 001234567").is_empty());
        // Marking words inside ordinary sentences.
        assert!(kinds("Ця інформація є конфіденційною, як і draft плану.").is_empty());
        assert!(kinds(
            "Ми обговорили confidential computing та restricted mode у звіті щодо платформи."
        )
        .is_empty());
        assert!(kinds("Стільниця з ДСП товщиною 18 мм, колір дуб сонома").is_empty());
        // RNOKPP without context must look like a birth date (no leading zero).
        assert!(!kinds("0501234567").contains(&PiiKind::Rnokpp));
    }

    #[test]
    fn markings_as_markings() {
        let t = "ДСК\nПримірник № 2\n\nНАКАЗ №15\nпро порядок роботи\n\nТекст наказу.\n\nDRAFT";
        let hits = scan(t, "текст");
        let labels: Vec<String> = hits.iter().filter_map(|h| h.detail.clone()).collect();
        assert_eq!(labels, ["ДСК", "Draft"]);
        let t2 = "Гриф: Конфіденційно";
        assert_eq!(kinds(t2), [PiiKind::Marking]);
        // A state secret stamp alone is High; Critical needs personal data next to it.
        assert_eq!(scan("ЦІЛКОМ ТАЄМНО", "x")[0].sev, Severity::High);
        let r = mk_rnokpp("301234567");
        let (m, _) = sanitize(
            &foca_core::Metadata::default(),
            Some(&format!("ЦІЛКОМ ТАЄМНО\nРНОКПП {r}")),
        );
        let mk = m.pii.iter().find(|p| p.kind == "marking").unwrap();
        assert_eq!(mk.sev, Severity::Critical);
        let (m, _) = sanitize(
            &foca_core::Metadata::default(),
            Some("ДСК\nРНОКПП 3012345670"),
        );
        assert_ne!(
            m.pii.iter().find(|p| p.kind == "marking").unwrap().sev,
            Severity::Critical
        );
    }

    #[test]
    fn redact_masks_secrets_and_pii() {
        let r = mk_rnokpp("345678901");
        let t = format!("ІПН {r}; password = Sup3rS3cret!x; карта 4111111111111111. ДСК");
        let (red, labels) = redact(&t);
        assert!(
            !red.contains(&r) && !red.contains("4111111111111111"),
            "{red}"
        );
        assert!(!red.contains("Sup3rS3cret!x"), "{red}");
        assert!(red.contains("ДСК"));
        assert!(labels.iter().any(|l| l == "pii:rnokpp"));
        assert!(
            labels.iter().any(|l| l.starts_with("secret:")),
            "{labels:?}"
        );
        assert!(red.contains("{{s:41…11}}"));
    }

    #[test]
    fn hostile_input_is_cheap() {
        let big = "1".repeat(200_000) + &" 4".repeat(100_000);
        let t = std::time::Instant::now();
        let _ = scan(&big, "x");
        let _ = redact(&big);
        assert!(t.elapsed().as_secs() < 10);
        let _ = scan("UA", "x");
        let _ = scan("€€€€€€ ДСК", "x");
    }

    #[test]
    fn sanitize_masks_text_and_metadata() {
        let mut m = foca_core::Metadata::new(foca_core::DocFormat::Docx);
        m.description = Some("Картка 4111 1111 1111 1111 клієнта".into());
        m.fields
            .insert("vcf:01.tel".into(), "ІПН 3012345670".into());
        let text = "Договір\nРНОКПП 3012345670, IBAN UA213223130000026007233566001\n";
        let (mm, t) = sanitize(&m, Some(text));
        let t = t.unwrap();
        assert!(
            !t.contains("3012345670") && !t.contains("26007233566001"),
            "{t}"
        );
        let js = serde_json::to_string(&mm).unwrap();
        assert!(
            !js.contains("4111 1111 1111 1111") && !js.contains("3012345670"),
            "{js}"
        );
        let kinds: Vec<&str> = mm.pii.iter().map(|p| p.kind.as_str()).collect();
        assert!(
            kinds.contains(&"card") && kinds.contains(&"iban"),
            "{kinds:?}"
        );
        assert!(mm
            .pii
            .iter()
            .all(|p| p.samples.iter().all(|s| !s.contains("3012345670"))));
    }

    #[test]
    fn duplicate_pii_and_ua_certs_and_ru_seria_all_masked() {
        let r = mk_rnokpp("345678901");
        let text = format!(
            "Перша карта 4111 1111 1111 1111; друга карта 4111 1111 1111 1111;\nИПН1 {r}, ИПН2 {r}"
        );
        let (masked_text, _) = mask_pii(&text, "текст");
        assert!(!masked_text.contains("4111"), "{masked_text}");
        assert!(!masked_text.contains(&r), "{masked_text}");

        let (redacted, _) = redact(&text);
        assert!(!redacted.contains("4111"), "{redacted}");
        assert!(!redacted.contains(&r), "{redacted}");

        let mut m = foca_core::Metadata::new(foca_core::DocFormat::Pdf);
        m.fields
            .insert("signature:subject".into(), "TINUA-3012345679".into());
        let (mm, _) = sanitize(&m, None);
        let subj = mm.fields.get("signature:subject").unwrap();
        assert!(!subj.contains("3012345679"), "{subj}");

        assert!(kinds("серия КМ 123456").contains(&PiiKind::Passport));
        assert!(kinds("ID-карта 001234567").contains(&PiiKind::IdCard));
    }
}
