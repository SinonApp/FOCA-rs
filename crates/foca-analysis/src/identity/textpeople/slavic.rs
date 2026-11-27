//! Cyrillic names (Ukrainian, Russian, Belarusian, Kazakh): patronymics, case forms,
//! surnames with initials, capitalised surnames.

use super::lang::{registry, Case, Gender, Script};
use super::morph::{patronymic, surname_guess, surname_nom, title_case};
use super::{init_gap, is_cap, is_upper, spaced, Found, Kind, NameForm, Tok, Vocab};

fn cyr(w: &str) -> bool {
    w.chars()
        .filter(|c| c.is_alphabetic())
        .all(|c| Script::of(c) == Script::Cyrillic)
}

fn capish(w: &str) -> bool {
    is_cap(w) || is_upper(w)
}

/// A nominative given name (the word is not a case form of a name).
fn nom_given(w: &str) -> bool {
    registry().given(w).is_some_and(|g| g.case == Case::Nom)
}

/// Shape of a surname candidate; `strict` also rejects words the document uses in lowercase.
fn surname_tok(t: &Tok, v: &Vocab, strict: bool) -> bool {
    surname_shape(t, v, strict) && patronymic(t.text).is_none()
}

/// Surname shape without the patronymic check: `Попович`, `Короткевич` are surnames when they
/// stand where the surname goes next to a given name and a patronymic.
fn surname_shape(t: &Tok, v: &Vocab, strict: bool) -> bool {
    if t.kind != Kind::Word || !capish(t.text) || !cyr(t.text) {
        return false;
    }
    let n = t.text.chars().filter(|c| c.is_alphabetic()).count();
    if !(2..=30).contains(&n) || registry().stop(t.text) {
        return false;
    }
    !(strict && v.common(t.text))
}

/// A given name: from the dictionary, or (`unknown_ok`) any capitalised Cyrillic word that is
/// not a stop word, a surname-like word or an ordinary lowercase word of the document.
fn given_of(t: &Tok, v: &Vocab, unknown_ok: bool) -> Option<String> {
    let r = registry();
    if t.kind != Kind::Word || !capish(t.text) || !cyr(t.text) {
        return None;
    }
    if let Some(g) = r.given(t.text) {
        return Some(g.nom);
    }
    let ok = unknown_ok
        && t.text.chars().count() >= 3
        && !r.stop(t.text)
        && !v.common(t.text)
        && !r.surname_suffix(t.text)
        && patronymic(t.text).is_none();
    ok.then(|| title_case(t.text))
}

fn init_char(t: &Tok) -> char {
    t.text.chars().next().unwrap_or('?')
}

fn found(name: String, form: NameForm, s: usize, e: usize, lang: &'static str) -> Found {
    Found {
        name,
        form,
        s,
        e,
        lang,
    }
}

/// Matches a person starting at token `i`; returns it with the number of tokens used.
fn match_at(
    line: &str,
    t: &[Tok],
    i: usize,
    v: &Vocab,
    lang: &'static str,
) -> Option<(Found, usize)> {
    let r = registry();
    let w = |k: usize| t.get(i + k);
    let a = w(0)?;
    if let (Some(b), Some(c)) = (w(1), w(2)) {
        let words = b.kind == Kind::Word && c.kind == Kind::Word;
        if words && a.kind == Kind::Word && spaced(line, a, b) && spaced(line, b, c) {
            // `Доповідь Олени Миколаївни Коваленко`: a surname right after the patronymic makes
            // it Given Patronymic Surname starting at the next token.
            let gps_next = !r.surname_suffix(a.text)
                && !is_upper(a.text)
                && w(3).is_some_and(|d| {
                    spaced(line, c, d)
                        && surname_tok(d, v, false)
                        && r.given(d.text).is_none()
                        && (r.surname_suffix(d.text) || is_upper(d.text))
                });
            // Surname Given Patronymic. An unknown given name is accepted when the surname
            // looks like one (suffix or capitals): the patronymic is strong evidence.
            if let Some((p_nom, pg, pc)) = patronymic(c.text) {
                let sur_strong = r.surname_suffix(a.text) || is_upper(a.text);
                let given = given_of(b, v, sur_strong);
                if let Some(g_nom) = given {
                    if !gps_next && surname_shape(a, v, false) && !nom_given(a.text) {
                        let sur = surname_nom(a.text, pg, pc);
                        let name = format!("{sur} {g_nom} {p_nom}");
                        return Some((found(name, NameForm::Full, a.s, c.e, lang), 3));
                    }
                }
            }
            // Given Patronymic Surname.
            if let Some((p_nom, pg, pc)) = patronymic(b.text) {
                let sur_strong = r.surname_suffix(c.text) || is_upper(c.text);
                if let Some(g_nom) = given_of(a, v, sur_strong) {
                    if surname_shape(c, v, false) && r.given(c.text).is_none() {
                        let sur = surname_nom(c.text, pg, pc);
                        let name = format!("{sur} {g_nom} {p_nom}");
                        return Some((found(name, NameForm::Full, a.s, c.e, lang), 3));
                    }
                }
            }
        }
        // Surname I. I.
        if b.kind == Kind::Init
            && c.kind == Kind::Init
            && spaced(line, a, b)
            && init_gap(line, b, c)
            && cyr(b.text)
            && cyr(c.text)
            && surname_shape(a, v, true)
            && !nom_given(a.text)
            && line[c.e..].starts_with('.')
        {
            let name = format!(
                "{} {}.{}.",
                surname_guess(a.text),
                init_char(b),
                init_char(c)
            );
            return Some((found(name, NameForm::Initials, a.s, c.e + 1, lang), 3));
        }
        // I. I. Surname
        if a.kind == Kind::Init
            && b.kind == Kind::Init
            && init_gap(line, a, b)
            && init_gap(line, b, c)
            && cyr(a.text)
            && cyr(b.text)
            && surname_shape(c, v, true)
            && !nom_given(c.text)
            && !line[..a.s].ends_with('.')
        {
            let name = format!(
                "{} {}.{}.",
                surname_guess(c.text),
                init_char(a),
                init_char(b)
            );
            return Some((found(name, NameForm::Initials, a.s, c.e, lang), 3));
        }
    }
    let b = w(1)?;
    if a.kind != Kind::Word || b.kind != Kind::Word || !spaced(line, a, b) {
        return None;
    }
    if w(2).is_some_and(|c| spaced(line, b, c) && patronymic(c.text).is_some()) {
        return None;
    }
    // Given Surname (`Олена Коваленко`, `Олена КОВАЛЕНКО`, `Івану Петренку`).
    if let Some(g) = r.given(a.text) {
        let shape_ok = (is_cap(a.text) && capish(b.text)) || (is_upper(a.text) && is_upper(b.text));
        let strong = is_upper(b.text) && !is_upper(a.text);
        if shape_ok
            && cyr(a.text)
            && surname_tok(b, v, true)
            && r.given(b.text).is_none()
            && (r.surname_suffix(b.text) || strong)
            && (!r.ambiguous(&g.nom) || strong)
        {
            let gender = if g.gender == Gender::Unknown {
                Gender::Male
            } else {
                g.gender
            };
            let name = format!("{} {}", g.nom, surname_nom(b.text, gender, g.case));
            return Some((found(name, NameForm::GivenSurname, a.s, b.e, lang), 2));
        }
    }
    // Surname Given (lists), nominative only.
    if let Some(g) = r.given(b.text).filter(|g| g.case == Case::Nom) {
        let shape_ok = (is_cap(b.text) && capish(a.text)) || (is_upper(a.text) && is_upper(b.text));
        let after_ok =
            w(2).is_none_or(|c| !(spaced(line, b, c) && c.kind == Kind::Word && is_cap(c.text)));
        let strong = is_upper(a.text) && !is_upper(b.text);
        if shape_ok
            && cyr(b.text)
            && after_ok
            && surname_tok(a, v, true)
            && r.given(a.text).is_none()
            && (r.surname_suffix(a.text) || strong)
            && !r.ambiguous(&g.nom)
        {
            let name = format!("{} {}", g.nom, title_case(a.text));
            return Some((found(name, NameForm::GivenSurname, a.s, b.e, lang), 2));
        }
    }
    None
}

pub fn find(line: &str, t: &[Tok], v: &Vocab, lang: &'static str) -> Vec<Found> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < t.len() {
        if !t[i].text.chars().next().is_some_and(char::is_uppercase)
            || Script::of_word(t[i].text) != Script::Cyrillic
        {
            i += 1;
            continue;
        }
        match match_at(line, t, i, v, lang) {
            Some((f, used)) => {
                out.push(f);
                i += used;
            }
            None => i += 1,
        }
    }
    out
}
