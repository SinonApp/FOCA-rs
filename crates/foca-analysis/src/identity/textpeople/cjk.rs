//! Chinese, Japanese and Korean names: family name first, usually without a space (Korean
//! separates words). A family name from the dictionary followed by one to three characters
//! counts only with a cue: a field label before it (`姓名：`, `担当者`, `성명`), a title or
//! honorific right after it (`先生`, `様`, `님`, `教授`) or a standalone short cell.

use super::lang::{registry, Script};
use super::{Found, NameForm};

fn is_han(c: char) -> bool {
    Script::of(c) == Script::Han && !('\u{3040}'..='\u{30ff}').contains(&c)
}

fn is_hangul(c: char) -> bool {
    Script::of(c) == Script::Hangul
}

/// Runs of one script: (byte start, byte end).
fn runs(line: &str, f: fn(char) -> bool) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in line.char_indices() {
        match (f(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, line.len()));
    }
    out
}

/// A label ends right before `s` (`姓名：`, `担当者:`, `성명 `).
fn labelled(line: &str, s: usize) -> bool {
    let before = line[..s].trim_end_matches([' ', '\u{3000}', ':', '：', '\t']);
    registry()
        .labels()
        .iter()
        .any(|l| !l.is_empty() && before.ends_with(l.as_str()))
}

/// An honorific or title word starts at `e`, possibly after a space.
fn after_word(line: &str, e: usize) -> Option<usize> {
    let rest = &line[e..];
    let trimmed = rest.trim_start_matches([' ', '\u{3000}']);
    let skip = rest.len() - trimmed.len();
    let r = registry();
    // Longest first: try 4, 3, 2, 1 characters.
    let cs: Vec<(usize, char)> = trimmed.char_indices().take(4).collect();
    for n in (1..=cs.len()).rev() {
        let end = cs.get(n).map(|x| x.0).unwrap_or(trimmed.len());
        if r.after(&trimmed[..end]) {
            return Some(e + skip + end);
        }
    }
    None
}

fn standalone(line: &str, s: usize, e: usize) -> bool {
    let left = line[..s].chars().next_back();
    let right = line[e..].chars().next();
    let edge = |c: Option<char>| {
        c.is_none_or(|c| c.is_whitespace() || "|,，、;；()（）[]【】/".contains(c))
    };
    edge(left) && edge(right) && line.trim().chars().count() <= 40
}

fn han_names(line: &str, lang: &'static str, out: &mut Vec<Found>) {
    let r = registry();
    // Given name of one or two (Chinese) or up to three (Japanese) characters.
    let max_given = if lang == "ja" { 3 } else { 2 };
    // `佐藤 太郎` / `王 伟`: family run + space + 1-3 character run, with a cue.
    let rr = runs(line, is_han);
    for w in rr.windows(2) {
        let ((a0, a1), (b0, b1)) = (w[0], w[1]);
        let gap = &line[a1..b0];
        let fam = &line[a0..a1];
        let gn = line[b0..b1].chars().count();
        if !(gap == " " || gap == "\u{3000}")
            || !(1..=3).contains(&gn)
            || !r.family(Script::Han, fam)
        {
            continue;
        }
        if out.iter().any(|f| f.s < b1 && a0 < f.e) {
            continue;
        }
        if labelled(line, a0) || after_word(line, b1).is_some() || standalone(line, a0, b1) {
            out.push(Found {
                name: format!("{fam} {}", &line[b0..b1]),
                form: NameForm::GivenSurname,
                s: a0,
                e: b1,
                lang,
            });
        }
    }
    for (rs, re) in runs(line, is_han) {
        let chars: Vec<usize> = line[rs..re].char_indices().map(|(i, _)| rs + i).collect();
        let n = chars.len();
        let pos = |k: usize| chars.get(k).copied().unwrap_or(re);
        let mut k = 0;
        'start: while k + 1 < n {
            for fam_len in [2, 1] {
                if k + fam_len >= n || !r.family(Script::Han, &line[pos(k)..pos(k + fam_len)]) {
                    continue;
                }
                for g in (1..=max_given).rev() {
                    let end_k = k + fam_len + g;
                    if end_k > n {
                        continue;
                    }
                    let (s, e) = (pos(k), pos(end_k));
                    if r.stop(&line[s..e]) {
                        continue;
                    }
                    let cue_after = after_word(line, e).is_some();
                    // Inside a run only a title or honorific right after the name counts;
                    // a whole run also counts after a label or as a standalone cell.
                    let whole = k == 0 && end_k == n;
                    let ok = cue_after || (whole && (labelled(line, s) || standalone(line, s, e)));
                    if ok && !out.iter().any(|f| f.s < e && s < f.e) {
                        out.push(Found {
                            name: line[s..e].to_string(),
                            form: NameForm::GivenSurname,
                            s,
                            e,
                            lang,
                        });
                        k = end_k;
                        continue 'start;
                    }
                }
            }
            k += 1;
        }
    }
}

fn hangul_names(line: &str, out: &mut Vec<Found>) {
    let r = registry();
    for (s, e) in runs(line, is_hangul) {
        let word = &line[s..e];
        let cs: Vec<(usize, char)> = word.char_indices().collect();
        // Strip an attached honorific (`김민수님`, `박지훈씨`, `이수진교수`).
        let mut end = word.len();
        let mut cued = false;
        for k in (2..cs.len()).rev() {
            if r.after(&word[cs[k].0..]) {
                end = cs[k].0;
                cued = true;
                break;
            }
        }
        let name = &word[..end];
        let n = name.chars().count();
        if !(2..=4).contains(&n) || r.stop(name) {
            continue;
        }
        let fam2: String = name.chars().take(2).collect();
        let fam1: String = name.chars().take(1).collect();
        let fam_ok = (n >= 3 && r.family(Script::Hangul, &fam2)) || r.family(Script::Hangul, &fam1);
        if !fam_ok || r.function_word(name) {
            continue;
        }
        let cue = cued || after_word(line, e).is_some() || labelled(line, s);
        if cue || (n == 3 && standalone(line, s, e)) {
            out.push(Found {
                name: name.to_string(),
                form: NameForm::GivenSurname,
                s,
                e: s + end,
                lang: "ko",
            });
        }
    }
}

pub fn find(line: &str, doc_lang: &'static str) -> Vec<Found> {
    let mut out = Vec::new();
    if line.chars().any(is_han) {
        let lang =
            if doc_lang == "ja" || line.chars().any(|c| ('\u{3040}'..='\u{30ff}').contains(&c)) {
                "ja"
            } else {
                "zh"
            };
        han_names(line, lang, &mut out);
    }
    if line.chars().any(is_hangul) {
        hangul_names(line, &mut out);
    }
    out
}
