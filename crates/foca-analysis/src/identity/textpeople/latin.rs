//! Latin-script names (English, German, French, Spanish, Portuguese, Italian, Polish, Czech,
//! Turkish, transliterated Arabic/Persian/Hebrew/Slavic): given name + optional middle names
//! or initials + optional particles (`von`, `de la`, `bin`) + surname + optional suffix
//! (`Jr.`, `III`), `Last, First`, initials (`J. R. Smith`, `Smith J.`), honorifics
//! (`Dr.`, `Herr`, `Mme`).

use super::lang::{fold, registry, Script};
use super::morph::title_case;
use super::{init_gap, is_cap, is_upper, spaced, Found, Kind, NameForm, Tok, Vocab};

fn latin(t: &Tok) -> bool {
    Script::of_word(t.text) == Script::Latin
}

fn capish(w: &str) -> bool {
    is_cap(w) || (is_upper(w) && w.chars().count() >= 3)
}

/// A surname candidate: capitalised Latin word, not a stop word, not a given name only, not
/// written in lowercase elsewhere in the document.
fn surname_ok(t: &Tok, v: &Vocab) -> bool {
    let r = registry();
    t.kind == Kind::Word
        && latin(t)
        && capish(t.text)
        && t.text.chars().count() >= 2
        && !t
            .text
            .split('-')
            .skip(1)
            .any(|p| p.starts_with(char::is_lowercase))
        && !r.stop(t.text)
        && !r.honorific(t.text)
        && !r.function_word(t.text)
        && !v.common(t.text)
}

fn given_ok(t: &Tok) -> bool {
    let r = registry();
    t.kind == Kind::Word
        && latin(t)
        && is_cap(t.text)
        && r.given(t.text).is_some()
        && !r.stop(t.text)
}

fn disp(w: &str) -> String {
    if is_upper(w) {
        title_case(w)
    } else {
        w.to_string()
    }
}

/// Gap between tokens of one name: spaces, or an initial's dot.
fn joined(line: &str, a: &Tok, b: &Tok) -> bool {
    if a.kind == Kind::Init {
        init_gap(line, a, b)
    } else {
        spaced(line, a, b)
    }
}

/// Extends a name to the right over particles, a surname, an optional second surname
/// (Spanish/Portuguese) and a suffix. Returns (surname parts, last token index used).
fn tail(line: &str, t: &[Tok], from: usize, v: &Vocab, lang: &str) -> Option<(Vec<String>, usize)> {
    let r = registry();
    let mut parts: Vec<String> = Vec::new();
    let mut k = from;
    // Particles: `van der`, `de la`, `bin`, `al`.
    while let Some(p) = t.get(k) {
        let prev = &t[k - 1];
        let lower = p.text.chars().next().is_some_and(char::is_lowercase);
        // `De Luca`, `Di Maio`, `Van Dyke`: a capitalised particle needs a surname after it.
        let cap_ok = !lower
            && t.get(k + 1).is_some_and(|n| {
                spaced(line, p, n) && surname_ok(n, v) && r.given(n.text).is_none()
            });
        if p.kind == Kind::Word && r.particle(p.text) && (lower || cap_ok) && joined(line, prev, p)
        {
            parts.push(p.text.to_string());
            k += 1;
        } else {
            break;
        }
    }
    let s = t.get(k)?;
    if !joined(line, &t[k - 1], s) || !surname_ok(s, v) {
        return None;
    }
    // A second capitalised given name is a middle name, not the surname, when more follows.
    parts.push(disp(s.text));
    let mut last = k;
    let compound = matches!(lang, "es" | "pt")
        || t.get(k + 1)
            .is_some_and(|n| n.kind == Kind::Word && fold(n.text) == "y");
    if compound {
        let mut j = k + 1;
        if t.get(j).is_some_and(|n| {
            fold(n.text) == "y"
                || r.particle(n.text) && n.text.chars().next().is_some_and(char::is_lowercase)
        }) {
            j += 1;
        }
        if let Some(n) = t.get(j) {
            if joined(line, &t[j - 1], n) && surname_ok(n, v) && r.given(n.text).is_none() {
                for x in &t[k + 1..=j] {
                    parts.push(disp(x.text));
                }
                last = j;
            }
        }
    }
    if let Some(n) = t.get(last + 1) {
        let gap = &line[t[last].e..n.s];
        if (gap.trim() == "," || gap.trim().is_empty())
            && gap.len() <= 3
            && r.after(n.text)
            && !n.text.chars().all(char::is_lowercase)
        {
            parts.push(n.text.trim_end_matches('.').to_string());
            last += 1;
        }
    }
    Some((parts, last))
}

fn match_at(
    line: &str,
    t: &[Tok],
    i: usize,
    v: &Vocab,
    lang: &'static str,
) -> Option<(Found, usize)> {
    let r = registry();
    let a = t.get(i)?;
    let mk = |name: String, form, s, e| Found {
        name,
        form,
        s,
        e,
        lang,
    };
    // Honorific + two or more capitalised words: a name even without a dictionary hit.
    if a.kind == Kind::Word && r.honorific(a.text) && latin(a) {
        let mut k = i + 1;
        if line[a.e..].starts_with('.') {
            // `Dr.` / `Prof. Dr.`
        }
        while t.get(k).is_some_and(|x| r.honorific(x.text)) {
            k += 1;
        }
        let first = t.get(k)?;
        let gap = &line[t[k - 1].e..first.s];
        if gap.trim_start_matches('.').trim().is_empty()
            && gap.len() <= 4
            && first.kind == Kind::Word
            && capish(first.text)
            && !r.stop(first.text)
            && latin(first)
        {
            if let Some((parts, last)) = tail(line, t, k + 1, v, lang) {
                let name = format!("{} {}", disp(first.text), parts.join(" "));
                return Some((
                    mk(name, NameForm::GivenSurname, first.s, t[last].e),
                    last + 1 - i,
                ));
            }
        }
    }
    // Given [Middle | I.]* [particles] Surname [Suffix].
    if given_ok(a)
        && !(r.ambiguous(a.text)
            && t.get(i + 1)
                .is_some_and(|n| n.kind != Kind::Init && !is_upper(n.text)))
    {
        let mut k = i + 1;
        let mut middle: Vec<String> = Vec::new();
        while let Some(m) = t.get(k) {
            let next_is_name = t
                .get(k + 1)
                .is_some_and(|n| joined(line, m, n) && n.kind == Kind::Word && capish(n.text));
            if m.kind == Kind::Init && latin(m) && joined(line, &t[k - 1], m) && middle.len() < 3 {
                middle.push(format!("{}.", m.text));
                k += 1;
            } else if given_ok(m) && next_is_name && joined(line, &t[k - 1], m) && middle.len() < 2
            {
                middle.push(m.text.to_string());
                k += 1;
            } else {
                break;
            }
        }
        if let Some((parts, last)) = tail(line, t, k, v, lang) {
            // The surname must not be a plain given name unless it is in capitals.
            let sur_tok = &t[last.min(t.len() - 1)];
            // (`Mary Ann` is two given names; `Jean-Pierre Martin` is a person).
            let only_given = parts.len() == 1
                && r.given(sur_tok.text).is_some()
                && !is_upper(sur_tok.text)
                && !a.text.contains('-')
                && middle.is_empty();
            if !only_given {
                let mut name = a.text.to_string();
                for m in &middle {
                    name.push(' ');
                    name.push_str(m);
                }
                name.push(' ');
                name.push_str(&parts.join(" "));
                let form = if middle.is_empty() {
                    NameForm::GivenSurname
                } else {
                    NameForm::Full
                };
                return Some((mk(name, form, a.s, t[last].e), last + 1 - i));
            }
        }
    }
    // Last, First [Middle]: `Carter, Emily`.
    if let (Some(b), true) = (t.get(i + 1), surname_ok(a, v)) {
        let gap = &line[a.e..b.s];
        if gap.trim() == "," && gap.len() <= 3 && given_ok(b) && r.given(a.text).is_none() {
            let follow = t.get(i + 2).is_some_and(|c| {
                spaced(line, b, c)
                    && c.kind == Kind::Word
                    && capish(c.text)
                    && r.given(c.text).is_none()
            });
            if !follow {
                return Some((
                    mk(
                        format!("{} {}", b.text, disp(a.text)),
                        NameForm::GivenSurname,
                        a.s,
                        b.e,
                    ),
                    2,
                ));
            }
        }
    }
    // Initials: `J. Smith`, `J.R. Smith`.
    if a.kind == Kind::Init
        && latin(a)
        && !line[..a.s].ends_with('.')
        && !line[..a.s]
            .trim_end()
            .ends_with(|c: char| c.is_alphanumeric() && c.is_lowercase())
    {
        let mut k = i;
        let mut inits = String::new();
        while let Some(x) = t.get(k) {
            if x.kind == Kind::Init && latin(x) && (k == i || init_gap(line, &t[k - 1], x)) {
                inits.push_str(x.text);
                inits.push('.');
                k += 1;
            } else {
                break;
            }
        }
        if let Some((parts, last)) = tail(line, t, k, v, lang) {
            let sur = &t[last.min(t.len() - 1)];
            if r.given(sur.text).is_none()
                && (inits.len() >= 4 || r.surname_suffix(sur.text) || sur.text.chars().count() >= 4)
            {
                return Some((
                    mk(
                        format!("{inits} {}", parts.join(" ")),
                        NameForm::Initials,
                        a.s,
                        t[last].e,
                    ),
                    last + 1 - i,
                ));
            }
        }
    }
    // Citation style: `Smith J.`, `Kowalski J. A.`.
    if surname_ok(a, v) && r.given(a.text).is_none() {
        let mut k = i + 1;
        let mut inits = String::new();
        while let Some(x) = t.get(k) {
            if x.kind == Kind::Init && latin(x) && joined(line, &t[k - 1], x) && inits.len() < 6 {
                inits.push_str(x.text);
                inits.push('.');
                k += 1;
            } else {
                break;
            }
        }
        let after = t.get(k - 1).map(|x| &line[x.e..]).unwrap_or("");
        let end_ok = after.starts_with('.')
            && after[1..].trim_start().chars().next().is_none_or(|c| {
                matches!(c, ',' | ';' | '(' | ')') || c.is_ascii_digit() || c.is_uppercase()
            });
        let cited = after
            .get(1..)
            .is_some_and(|x| x.trim_start().starts_with(['(', ',', ';']));
        if !inits.is_empty() && end_ok && (inits.len() >= 4 || cited || r.surname_suffix(a.text)) {
            let e = t[k - 1].e + 1;
            return Some((
                mk(
                    format!("{inits} {}", disp(a.text)),
                    NameForm::Initials,
                    a.s,
                    e,
                ),
                k - i,
            ));
        }
    }
    None
}

pub fn find(line: &str, t: &[Tok], v: &Vocab, lang: &'static str) -> Vec<Found> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < t.len() {
        if !t[i].text.chars().next().is_some_and(char::is_uppercase) || !latin(&t[i]) {
            i += 1;
            continue;
        }
        match match_at(line, t, i, v, lang) {
            Some((f, used)) => {
                out.push(f);
                i += used.max(1);
            }
            None => i += 1,
        }
    }
    out
}
