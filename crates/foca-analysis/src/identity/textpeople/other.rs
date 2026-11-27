//! Arabic, Persian, Hebrew, Georgian and Armenian script names: a given name from the
//! dictionary (or an honorific) followed by one to three words of the same script, with
//! particles (`بن`, `ابن`, `أبو`) allowed in between; or any word followed by a word with a
//! strong surname suffix (`-შვილი`, `-ძე`, `-յան`).

use super::lang::{registry, Script};
use super::{spaced, Found, Kind, NameForm, Tok};

fn same(t: &Tok, s: Script) -> bool {
    t.kind == Kind::Word && Script::of_word(t.text) == s
}

fn name_word(t: &Tok, s: Script) -> bool {
    let r = registry();
    same(t, s)
        && t.text.chars().count() >= 2
        && !r.stop(t.text)
        && !r.function_word(t.text)
        && !r.honorific(t.text)
}

pub fn find(line: &str, t: &[Tok], script: Script, lang: &'static str) -> Vec<Found> {
    let r = registry();
    let mut out = Vec::new();
    let mut i = 0;
    while i < t.len() {
        let a = &t[i];
        if !same(a, script) {
            i += 1;
            continue;
        }
        let honor = r.honorific(a.text);
        let start = if honor { i + 1 } else { i };
        let Some(first) = t.get(start) else { break };
        let given = r.given(first.text).is_some() && name_word(first, script);
        let cased = matches!(script, Script::Armenian);
        // Strong suffix pattern: `Ნინო ბერიძე`, `Արամ Պետրոսյան`.
        let suffix_next = t.get(start + 1).is_some_and(|b| {
            name_word(b, script) && spaced(line, first, b) && r.surname_suffix(b.text)
        });
        if !(given
            || (honor && name_word(first, script))
            || (suffix_next && name_word(first, script)))
        {
            i += 1;
            continue;
        }
        if cased && !first.text.chars().next().is_some_and(char::is_uppercase) {
            i += 1;
            continue;
        }
        let mut k = start + 1;
        let mut words = vec![first.text.to_string()];
        while let Some(b) = t.get(k) {
            if !spaced(line, &t[k - 1], b) || words.len() >= 4 {
                break;
            }
            if r.particle(b.text) && same(b, script) {
                if t.get(k + 1)
                    .is_some_and(|c| name_word(c, script) && spaced(line, b, c))
                {
                    words.push(b.text.to_string());
                    k += 1;
                    continue;
                }
                break;
            }
            if !name_word(b, script)
                || (cased && !b.text.chars().next().is_some_and(char::is_uppercase))
            {
                break;
            }
            // Without a surname suffix keep at most given + two names (Arabic nasab chains are
            // cut at the first function word anyway).
            words.push(b.text.to_string());
            k += 1;
            if !matches!(script, Script::Arabic) && words.len() >= 2 {
                break;
            }
        }
        if words.len() >= 2 {
            out.push(Found {
                name: words.join(" "),
                form: NameForm::GivenSurname,
                s: first.s,
                e: t[k - 1].e,
                lang,
            });
            i = k;
        } else {
            i += 1;
        }
    }
    out
}
