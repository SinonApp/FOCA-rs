//! People named in document text, in many languages: full names, surnames with initials,
//! positions, academic titles, units, signature blocks and the contacts written next to
//! them.
//!
//! Architecture:
//!
//! * [`lang`] loads one data file per language (`signatures/people/<code>.txt`: given names,
//!   family names, particles, honorifics, labels, positions, stop words) into one registry.
//! * Text is normalised (NFC for common combining marks, NBSP, apostrophe variants), the
//!   document language is guessed from function words and every line is routed by script:
//!   * Cyrillic ([`slavic`]): patronymics and case forms (UK, RU, BE, KK),
//!   * Latin ([`latin`]): given name + [middle] + [particles] + surname + [suffix],
//!     `Last, First`, initials, honorifics (`Dr.`, `Herr`, `Mme`),
//!   * Han / Hangul ([`cjk`]): family name first, no spaces; needs a label, a title after
//!     the name or a standalone cell,
//!   * Arabic, Hebrew, Georgian, Armenian ([`other`]): given-name dictionary or surname
//!     suffixes.
//! * [`titles`] finds the position, degree and unit around a name and signature blocks;
//!   [`contacts`] finds phones, e-mails, identifiers and links them to the nearest name.
//!
//! The cost is linear in the text size: tokens per line, no backtracking regular
//! expressions over the whole text.

mod cjk;
mod contacts;
mod lang;
mod latin;
mod merge;
mod morph;
mod other;
mod slavic;
mod titles;

use std::collections::HashSet;

pub use contacts::{ContactKind, PhoneHit};
use lang::{fold, registry, Script};
pub use merge::{attrs, doc_counts, identities, phones, Attrs};

/// Text size scanned per document.
pub const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
/// People kept per document.
pub const MAX_PEOPLE: usize = 2000;

/// How a person was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NameForm {
    /// Surname, given name and patronymic (or given + middle + surname).
    Full,
    /// Given name and surname.
    GivenSurname,
    /// Surname and initials.
    Initials,
}

/// One mention of a person in a document text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mention {
    /// Normalised spelling (nominative where the case was known): `Петренко Іван Васильович`,
    /// `Петренко І.В.`, `Emily Carter`, `王伟`.
    pub name: String,
    pub form: NameForm,
    /// Language code of the rule set that matched (`uk`, `de`, `zh`, ...).
    pub lang: &'static str,
    /// 1-based line number.
    pub line: usize,
    /// Position / academic title / degree next to the name (`доцент, к.ю.н.`, `CTO`).
    pub title: Option<String>,
    /// Department, faculty or unit from the same line or the nearest heading.
    pub unit: Option<String>,
    /// Name inside a signature block (`_____ /Петренко І.В./`, `(підпис)`, `М.П.`).
    pub signatory: bool,
    /// Name inside a bibliography entry or citation (a cited author, not a staff member).
    pub cited: bool,
    /// Phone numbers on the same line or block (raw values).
    pub phones: Vec<String>,
    /// E-mail addresses on the same line or block.
    pub emails: Vec<String>,
    /// Kinds of personal identifiers next to the name (`rnokpp`, `birth_date`, ...).
    pub ids: Vec<ContactKind>,
}

/// Everything found in one document text.
#[derive(Debug, Clone, Default)]
pub struct TextScan {
    /// Guessed document language.
    pub lang: &'static str,
    pub people: Vec<Mention>,
    pub phones: Vec<PhoneHit>,
    /// E-mail addresses including obfuscated forms.
    pub emails: Vec<String>,
    /// Counts of contact and identifier kinds found anywhere in the text.
    pub counts: Vec<(ContactKind, u32)>,
}

/// A name matched inside a line (byte range within the line).
pub(crate) struct Found {
    pub name: String,
    pub form: NameForm,
    pub s: usize,
    pub e: usize,
    pub lang: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Word,
    /// A single capital letter followed by a dot.
    Init,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Tok<'a> {
    pub s: usize,
    pub e: usize,
    pub text: &'a str,
    pub kind: Kind,
}

pub(crate) fn is_apos(c: char) -> bool {
    matches!(c, '\'' | '’' | 'ʼ' | '`')
}

/// Splits a line into words and initials (byte offsets within the line).
pub(crate) fn tokens(line: &str) -> Vec<Tok<'_>> {
    let mut out = Vec::new();
    let cs: Vec<(usize, char)> = line.char_indices().collect();
    let mut i = 0;
    while i < cs.len() {
        let (s, c) = cs[i];
        if !c.is_alphabetic() {
            i += 1;
            continue;
        }
        let sc = Script::of(c);
        let mut j = i + 1;
        while j < cs.len() {
            let ch = cs[j].1;
            let inner =
                (is_apos(ch) || ch == '-') && cs.get(j + 1).is_some_and(|n| n.1.is_alphabetic());
            // Combining marks (Arabic harakat, Hebrew points) stay inside the word.
            let mark = matches!(ch as u32, 0x300..=0x36f | 0x591..=0x5c7 | 0x64b..=0x65f | 0x670);
            if (ch.is_alphabetic() && (Script::of(ch) == sc || sc == Script::Other))
                || inner
                || mark
            {
                j += 1;
            } else {
                break;
            }
        }
        let e = cs.get(j).map(|x| x.0).unwrap_or(line.len());
        let text = &line[s..e];
        let single = j == i + 1;
        let kind = if single && c.is_uppercase() && cs.get(j).is_some_and(|n| n.1 == '.') {
            Kind::Init
        } else {
            Kind::Word
        };
        out.push(Tok { s, e, text, kind });
        i = j;
    }
    out
}

pub(crate) fn is_upper(w: &str) -> bool {
    w.chars().filter(|c| c.is_alphabetic()).count() >= 2 && !w.chars().any(char::is_lowercase)
}

/// `Петренко`, `Коваль-Лисенко`, `O'Connor`, `McDonald`, `al-Rashid`, `d'Alembert`: a capital
/// first letter (after a lowercase particle prefix), the rest lowercase except after a
/// separator or a `Mc`/`Mac`/`De`/`Di`/`La`/`Le`/`Van` prefix.
pub(crate) fn is_cap(w: &str) -> bool {
    let core = [
        "al-", "el-", "ad-", "as-", "ash-", "an-", "ar-", "d'", "l'", "o'", "d’", "l’",
    ]
    .iter()
    .find_map(|p| w.strip_prefix(p))
    .unwrap_or(w);
    let mut cs = core.chars();
    let Some(f) = cs.next() else { return false };
    if !f.is_uppercase() {
        return false;
    }
    let mut prev_sep = false;
    let mut n = 1;
    for c in cs {
        n += 1;
        if c.is_uppercase() && !prev_sep {
            let head: String = core.chars().take(n - 1).collect();
            if !["Mc", "Mac", "De", "Di", "La", "Le", "Van", "Fitz"].contains(&head.as_str()) {
                return false;
            }
        }
        prev_sep = c == '-' || is_apos(c);
    }
    core.chars().count() >= 2
}

/// Separator between two tokens: only spaces (no comma, dash or other punctuation).
pub(crate) fn spaced(line: &str, a: &Tok, b: &Tok) -> bool {
    let gap = &line[a.e..b.s];
    gap.chars().all(|c| c == ' ' || c == '\u{a0}' || c == '\t') && gap.len() <= 12
}

/// Separator after an initial: its dot and optional spaces.
pub(crate) fn init_gap(line: &str, a: &Tok, b: &Tok) -> bool {
    let gap = &line[a.e..b.s];
    let mut cs = gap.chars();
    cs.next() == Some('.') && cs.all(|c| c == ' ' || c == '\u{a0}') && gap.len() <= 4
}

/// Per-document lowercase vocabulary: a capitalised word that the document also writes in
/// lowercase is an ordinary word, not a surname.
pub(crate) struct Vocab(HashSet<String>);

impl Vocab {
    fn new(text: &str) -> Self {
        let mut set = HashSet::new();
        let word = |c: char| c.is_alphabetic() || is_apos(c) || c == '-';
        let mut start: Option<usize> = None;
        let mut prev: Option<char> = None;
        let mut add = |s: usize, e: usize, before: Option<char>, after: Option<char>| {
            let w = &text[s..e];
            // Parts of e-mail addresses, URLs and identifiers are not vocabulary.
            let glued = |c: Option<char>| {
                c.is_some_and(|c| matches!(c, '.' | '@' | '/' | '_' | ':') || c.is_ascii_digit())
            };
            if w.chars().next().is_some_and(char::is_lowercase)
                && !w.chars().any(char::is_uppercase)
                && w.chars().count() >= 3
                && !glued(before)
                && !glued(after)
            {
                set.insert(fold(w));
            }
        };
        let mut before: Option<char> = None;
        for (i, c) in text.char_indices() {
            match (word(c), start) {
                (true, None) => {
                    start = Some(i);
                    before = prev;
                }
                (false, Some(s)) => {
                    add(s, i, before, Some(c));
                    start = None;
                }
                _ => {}
            }
            prev = Some(c);
        }
        if let Some(s) = start {
            add(s, text.len(), before, None);
        }
        Vocab(set)
    }

    pub fn common(&self, w: &str) -> bool {
        self.0.contains(&fold(w))
    }
}

/// Composes the most common decomposed sequences (NFC for Latin accents and Cyrillic `й`,
/// `ї`, `ё`), maps NBSP and narrow spaces to a space and apostrophe variants to `'`.
pub fn normalize(text: &str) -> std::borrow::Cow<'_, str> {
    let needs = text.chars().any(|c| {
        matches!(
            c as u32,
            0x300..=0x30c | 0xa0 | 0x2007 | 0x202f | 0x2019 | 0x2bc
        )
    });
    if !needs {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let mark = c as u32;
        if (0x300..=0x30c).contains(&mark) {
            if let Some(prev) = out.pop() {
                match compose(prev, c) {
                    Some(x) => out.push(x),
                    None => {
                        out.push(prev);
                        out.push(c);
                    }
                }
                continue;
            }
        }
        out.push(match c {
            '\u{a0}' | '\u{2007}' | '\u{202f}' => ' ',
            '\u{2019}' | '\u{2bc}' => '\'',
            c => c,
        });
    }
    std::borrow::Cow::Owned(out)
}

fn compose(base: char, mark: char) -> Option<char> {
    const TABLE: &[(char, char, char)] = &[
        ('и', '\u{306}', 'й'),
        ('И', '\u{306}', 'Й'),
        ('і', '\u{308}', 'ї'),
        ('І', '\u{308}', 'Ї'),
        ('е', '\u{308}', 'ё'),
        ('Е', '\u{308}', 'Ё'),
        ('у', '\u{306}', 'ў'),
        ('У', '\u{306}', 'Ў'),
        ('a', '\u{301}', 'á'),
        ('e', '\u{301}', 'é'),
        ('i', '\u{301}', 'í'),
        ('o', '\u{301}', 'ó'),
        ('u', '\u{301}', 'ú'),
        ('y', '\u{301}', 'ý'),
        ('A', '\u{301}', 'Á'),
        ('E', '\u{301}', 'É'),
        ('I', '\u{301}', 'Í'),
        ('O', '\u{301}', 'Ó'),
        ('U', '\u{301}', 'Ú'),
        ('a', '\u{300}', 'à'),
        ('e', '\u{300}', 'è'),
        ('i', '\u{300}', 'ì'),
        ('o', '\u{300}', 'ò'),
        ('u', '\u{300}', 'ù'),
        ('E', '\u{300}', 'È'),
        ('a', '\u{302}', 'â'),
        ('e', '\u{302}', 'ê'),
        ('i', '\u{302}', 'î'),
        ('o', '\u{302}', 'ô'),
        ('u', '\u{302}', 'û'),
        ('a', '\u{308}', 'ä'),
        ('e', '\u{308}', 'ë'),
        ('i', '\u{308}', 'ï'),
        ('o', '\u{308}', 'ö'),
        ('u', '\u{308}', 'ü'),
        ('A', '\u{308}', 'Ä'),
        ('O', '\u{308}', 'Ö'),
        ('U', '\u{308}', 'Ü'),
        ('a', '\u{303}', 'ã'),
        ('o', '\u{303}', 'õ'),
        ('n', '\u{303}', 'ñ'),
        ('N', '\u{303}', 'Ñ'),
        ('c', '\u{327}', 'ç'),
        ('C', '\u{327}', 'Ç'),
        ('s', '\u{30c}', 'š'),
        ('S', '\u{30c}', 'Š'),
        ('c', '\u{30c}', 'č'),
        ('C', '\u{30c}', 'Č'),
        ('z', '\u{30c}', 'ž'),
        ('Z', '\u{30c}', 'Ž'),
        ('r', '\u{30c}', 'ř'),
        ('R', '\u{30c}', 'Ř'),
        ('e', '\u{30c}', 'ě'),
        ('n', '\u{30c}', 'ň'),
        ('g', '\u{306}', 'ğ'),
        ('G', '\u{306}', 'Ğ'),
        ('s', '\u{327}', 'ş'),
        ('S', '\u{327}', 'Ş'),
    ];
    TABLE
        .iter()
        .find(|(b, m, _)| *b == base && *m == mark)
        .map(|(_, _, x)| *x)
}

/// Names in one line. Mixed lines run every rule set whose script occurs in the line.
fn find_in_line(line: &str, v: &Vocab, doc_lang: &'static str) -> Vec<Found> {
    let r = registry();
    let mut present = [false; 9];
    for c in line.chars().filter(|c| c.is_alphabetic()) {
        present[Script::of(c) as usize] = true;
    }
    let has = |s: Script| present[s as usize];
    let mut out: Vec<Found> = Vec::new();
    let t = tokens(line);
    if has(Script::Cyrillic) {
        out.extend(slavic::find(
            line,
            &t,
            v,
            r.lang_for(Script::Cyrillic, doc_lang),
        ));
    }
    if has(Script::Latin) {
        out.extend(latin::find(
            line,
            &t,
            v,
            r.lang_for(Script::Latin, doc_lang),
        ));
    }
    if has(Script::Han) || has(Script::Hangul) {
        out.extend(cjk::find(line, doc_lang));
    }
    for s in [
        Script::Arabic,
        Script::Hebrew,
        Script::Georgian,
        Script::Armenian,
    ] {
        if has(s) {
            out.extend(other::find(line, &t, s, r.lang_for(s, doc_lang)));
        }
    }
    out.sort_by_key(|f| (f.s, std::cmp::Reverse(f.e)));
    let mut kept: Vec<Found> = Vec::new();
    for f in out {
        if !kept.iter().any(|k| k.s < f.e && f.s < k.e) {
            kept.push(f);
        }
    }
    kept
}

/// Names of line `li`, also those that wrap onto the next line (`Петренко Іван` +
/// `Васильович`, `Петренко` + `Іван Васильович`): the head of the next line is appended when it
/// starts with a patronymic or a given name + patronymic. Matches are clamped to the line.
fn find_wrapped(lines: &[&str], li: usize, v: &Vocab, doc_lang: &'static str) -> Vec<Found> {
    let line = lines[li];
    let mut out = find_in_line(line, v, doc_lang);
    let Some(next) = lines.get(li + 1) else {
        return out;
    };
    let nt = tokens(next);
    let take = match nt.as_slice() {
        [a, b, ..] if registry().given(a.text).is_some() && morph::patronymic(b.text).is_some() => {
            2
        }
        [a, ..] if morph::patronymic(a.text).is_some() => 1,
        _ => 0,
    };
    if take == 0 || !next[..nt[0].s].trim().is_empty() {
        return out;
    }
    let tail_end = nt[take - 1].e;
    let joined = format!("{} {}", line.trim_end(), &next[nt[0].s..tail_end]);
    let cut = line.trim_end().len();
    for f in find_in_line(&joined, v, doc_lang) {
        if f.s < cut && f.e > cut && !out.iter().any(|o| o.s < f.e && f.s < o.e && o.e > cut) {
            out.retain(|o| !(o.s < f.e && f.s < o.e));
            out.push(Found { e: cut, ..f });
        }
    }
    out.sort_by_key(|f| f.s);
    out
}

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

/// Scans a document text for people and their contacts.
pub fn scan(text: &str) -> TextScan {
    let norm = normalize(clip(text, MAX_TEXT_BYTES));
    let text: &str = &norm;
    let r = registry();
    let doc_lang = r.guess(text);
    let vocab = Vocab::new(text);
    let lines: Vec<&str> = text.lines().collect();
    let found: Vec<Vec<Found>> = (0..lines.len())
        .map(|li| find_wrapped(&lines, li, &vocab, doc_lang))
        .collect();
    let cs = contacts::scan(text, &lines, doc_lang);
    let mut people = Vec::new();
    for (li, fs) in found.iter().enumerate() {
        for (k, f) in fs.iter().enumerate() {
            if people.len() >= MAX_PEOPLE {
                break;
            }
            let line = lines[li];
            let from = if k > 0 { fs[k - 1].e } else { 0 };
            let to = fs.get(k + 1).map(|n| n.s).unwrap_or(line.len());
            let ctx = titles::Ctx {
                lines: &lines,
                li,
                before: &line[from..f.s],
                after: &line[f.e..to],
                alone: fs.len() == 1,
            };
            let sig = titles::signatory(&ctx);
            let mut m = Mention {
                name: f.name.clone(),
                form: f.form,
                lang: f.lang,
                line: li + 1,
                title: titles::title(&ctx),
                unit: titles::unit(&ctx),
                signatory: sig,
                cited: !sig && titles::cited(&ctx),
                phones: vec![],
                emails: vec![],
                ids: vec![],
            };
            // Contacts on the same line after this name and before the next one; on lines
            // without names, the closest single-name line within two lines.
            for c in &cs.list {
                let own = if c.li == li {
                    (c.col >= f.s && c.col < to) || (fs.len() == 1)
                } else {
                    let d = c.li.abs_diff(li);
                    d <= 2
                        && fs.len() == 1
                        && found.get(c.li).is_some_and(Vec::is_empty)
                        && !(c.li.min(li)..=c.li.max(li))
                            .any(|x| x != li && found.get(x).is_some_and(|v| !v.is_empty()))
                        && nearest_name_line(&found, c.li) == Some(li)
                };
                if !own {
                    continue;
                }
                match (c.kind, &c.value) {
                    ("phone", Some(v)) if !m.phones.contains(v) => m.phones.push(v.clone()),
                    ("email", Some(v)) if !m.emails.contains(v) => m.emails.push(v.clone()),
                    ("phone" | "email" | "address" | "edrpou", _) => {}
                    (k, _) if !m.ids.contains(&k) => m.ids.push(k),
                    _ => {}
                }
            }
            people.push(m);
        }
    }
    let mut emails: Vec<String> = Vec::new();
    for c in cs.list.iter().filter(|c| c.kind == "email") {
        if let Some(v) = &c.value {
            if !emails.contains(v) {
                emails.push(v.clone());
            }
        }
    }
    TextScan {
        lang: doc_lang,
        people,
        phones: cs.phones.clone(),
        emails,
        counts: cs.counts(),
    }
}

/// The closest line with exactly one name (ties: the line above).
fn nearest_name_line(found: &[Vec<Found>], li: usize) -> Option<usize> {
    for d in 1..=2 {
        if li >= d && found[li - d].len() == 1 {
            return Some(li - d);
        }
        if found.get(li + d).is_some_and(|v| v.len() == 1) {
            return Some(li + d);
        }
    }
    None
}

#[cfg(test)]
mod tests;
